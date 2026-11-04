//! Clean-up for network state a previous session left behind.
//!
//! Both clients run this at startup, before any connect: a session that died
//! mid-tunnel (crash, forced kill, power loss) can leave hosts-file overrides,
//! WFP filters, an adapter in WinpkFilter tunnel mode and adapter settings
//! changed, and some of those survive a reboot.

/// Undo whatever a previous session left behind. Cheap on a healthy PC: the
/// heavier steps run only when a marker or a broken driver shows they are
/// needed.
pub fn recover_stale_network_state() {
    // Clean up any stale hosts-file entries from old proxy versions.
    crate::roblox_proxy::hosts::recover_stale();
    // Remove old WFP process-block filters from builds before dynamic WFP sessions.
    crate::vpn::wfp_block::cleanup_stale();
    // Reset any adapter left in WinpkFilter tunnel mode by a prior forced
    // exit. Marker-aware: escalates to verified resets with bounded retries
    // when a previous session died mid-tunnel (the "no internet after
    // SwiftTunnel" incident class).
    crate::vpn::recover_tunnel_mode_on_startup();
    // Recover adapter settings if the app crashed while connected.
    crate::vpn::recover_tso_on_startup();
    crate::vpn::recover_ipv6_on_startup();
    // Heavier remediation, run ONLY when there's real evidence a previous session
    // left state behind. The check below is all cheap peeks (three marker file
    // reads + one device-open probe) — no PowerShell, no netsh — so a healthy PC
    // short-circuits here and the UI reveals immediately. This is what lets the
    // self-heal "fix everything the Repair tab does" without lagging normal users:
    // the expensive steps only touch machines that are actually broken.
    #[cfg(windows)]
    {
        use crate::vpn::{SplitTunnelDriver, ipv6_recovery, tso_recovery, tunnel_mode_recovery};

        // A clean shutdown leaves no markers; their presence means a session died
        // mid-tunnel. A driver that's installed but won't open is the half-removed
        // state that blackholes traffic ("No internet, Secured").
        let marker_present = tunnel_mode_recovery::read_tunnel_mode_marker().is_some()
            || ipv6_recovery::read_ipv6_marker().is_some()
            || tso_recovery::read_tso_marker().is_some();
        let driver_broken =
            !SplitTunnelDriver::is_available() && SplitTunnelDriver::driver_install_evidence();

        // Always remove an enabled WinpkFilter adapter binding while SwiftTunnel
        // is disconnected. Most PCs tolerate the binding sitting enabled, but on
        // some network stacks it survives reboot/uninstall as "internet only
        // works after I reconnect SwiftTunnel". This is the same no-op-safe step
        // used by Repair -> Internet Recovery; connect re-enables it only on the
        // selected adapter when the tunnel actually starts.
        match SplitTunnelDriver::disable_leftover_winpkfilter_bindings() {
            Ok(disabled) if !disabled.is_empty() => log::info!(
                "Startup recovery: disabled leftover WinpkFilter binding on adapter(s): {}",
                disabled.join(", ")
            ),
            Ok(_) => {}
            Err(e) => log::warn!("Startup recovery: WinpkFilter binding cleanup failed: {e}"),
        }

        if marker_present || driver_broken {
            log::info!(
                "Startup recovery: leftover network state detected (markers={marker_present}, driver_broken={driver_broken}); running full self-heal"
            );

            // If the driver is installed but STILL can't be opened after the unbind,
            // the NDIS state is wedged. Do not restart or reinstall the kernel driver
            // automatically here; BSOD reports mean this path must fail closed and
            // let the UI ask for a clean Windows restart instead.
            let still_broken =
                !SplitTunnelDriver::is_available() && SplitTunnelDriver::driver_install_evidence();
            if still_broken {
                log::warn!(
                    "Startup recovery: driver still wedged after unbind; automatic NDISRD service restart skipped"
                );
            }
        }
    }
}
