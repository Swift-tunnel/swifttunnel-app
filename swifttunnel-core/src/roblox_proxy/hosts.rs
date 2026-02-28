//! Windows hosts-file management for the Roblox proxy.
//!
//! Adds / removes `127.66.0.1` entries for Roblox domains so that
//! Roblox's HTTPS traffic is redirected to the local TCP relay.
//! All entries are bookended with marker comments so they can be
//! identified and cleaned up reliably.

use log::{debug, info, warn};
use std::fs;
use std::path::PathBuf;

const MARKER_START: &str = "# SwiftTunnel Roblox Proxy - START";
const MARKER_END: &str = "# SwiftTunnel Roblox Proxy - END";
const LOOPBACK_IP: &str = "127.66.0.1";

/// Roblox domains to intercept via the local proxy.
pub const ROBLOX_DOMAINS: &[&str] = &[
    "clientsettings.roblox.com",
    "clientsettingscdn.roblox.com",
    "setup.rbxcdn.com",
    "roblox.com",
    "www.roblox.com",
    "apis.roblox.com",
    "auth.roblox.com",
    "avatar.roblox.com",
    "catalog.roblox.com",
    "games.roblox.com",
    "groups.roblox.com",
    "thumbnails.roblox.com",
    "users.roblox.com",
    "assetdelivery.roblox.com",
    "economy.roblox.com",
    "inventory.roblox.com",
];

fn hosts_path() -> PathBuf {
    PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
}

/// Append Roblox domain overrides to the Windows hosts file.
///
/// Existing SwiftTunnel entries are removed first (idempotent).
pub fn apply_overrides() -> Result<(), String> {
    let path = hosts_path();

    let content =
        fs::read_to_string(&path).map_err(|e| format!("Failed to read hosts file: {e}"))?;

    let clean = remove_marker_block(&content);

    let mut block = String::new();
    block.push_str(MARKER_START);
    block.push('\n');
    for domain in ROBLOX_DOMAINS {
        block.push_str(&format!("{LOOPBACK_IP} {domain}\n"));
    }
    block.push_str(MARKER_END);
    block.push('\n');

    let mut out = clean;
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&block);

    fs::write(&path, &out).map_err(|e| format!("Failed to write hosts file: {e}"))?;

    info!(
        "Applied {} Roblox domain overrides to hosts file",
        ROBLOX_DOMAINS.len()
    );

    flush_dns_cache();
    Ok(())
}

/// Remove any SwiftTunnel Roblox Proxy entries from the hosts file.
pub fn remove_overrides() -> Result<(), String> {
    let path = hosts_path();

    let content =
        fs::read_to_string(&path).map_err(|e| format!("Failed to read hosts file: {e}"))?;

    let clean = remove_marker_block(&content);

    if clean != content {
        fs::write(&path, &clean).map_err(|e| format!("Failed to write hosts file: {e}"))?;
        info!("Removed Roblox proxy overrides from hosts file");
        flush_dns_cache();
    }

    Ok(())
}

/// Called on app startup to clean up entries left by a previous crash.
pub fn recover_stale() {
    if let Err(e) = remove_overrides() {
        warn!("Failed to recover stale hosts entries: {e}");
    }
}

/// Returns `true` if the hosts file currently contains SwiftTunnel entries.
pub fn has_overrides() -> bool {
    let path = hosts_path();
    match fs::read_to_string(&path) {
        Ok(content) => content.contains(MARKER_START),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Remove the marker-delimited block from the hosts file content.
fn remove_marker_block(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let mut inside_block = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == MARKER_START {
            inside_block = true;
            continue;
        }
        if trimmed == MARKER_END {
            inside_block = false;
            continue;
        }

        if !inside_block {
            result.push_str(line);
            result.push('\n');
        }
    }

    // Collapse trailing blank lines to a single newline
    let trimmed = result.trim_end_matches('\n');
    if trimmed.is_empty() {
        return String::new();
    }
    let mut out = trimmed.to_string();
    out.push('\n');
    out
}

/// Flush the Windows DNS resolver cache (`ipconfig /flushdns`).
fn flush_dns_cache() {
    let output = crate::hidden_command("ipconfig").arg("/flushdns").output();

    match output {
        Ok(o) if o.status.success() => debug!("DNS cache flushed"),
        Ok(o) => warn!(
            "ipconfig /flushdns exited {}: {}",
            o.status,
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => warn!("Failed to run ipconfig /flushdns: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_marker_block_empty_input() {
        assert_eq!(remove_marker_block(""), "");
    }

    #[test]
    fn remove_marker_block_no_markers() {
        let input = "127.0.0.1 localhost\n::1 localhost\n";
        assert_eq!(remove_marker_block(input), input);
    }

    #[test]
    fn remove_marker_block_with_entries() {
        let input = "\
127.0.0.1 localhost
# SwiftTunnel Roblox Proxy - START
127.66.0.1 clientsettings.roblox.com
127.66.0.1 roblox.com
# SwiftTunnel Roblox Proxy - END
::1 localhost
";
        let expected = "127.0.0.1 localhost\n::1 localhost\n";
        assert_eq!(remove_marker_block(input), expected);
    }

    #[test]
    fn remove_marker_block_at_end_of_file() {
        let input = "\
127.0.0.1 localhost
# SwiftTunnel Roblox Proxy - START
127.66.0.1 clientsettings.roblox.com
# SwiftTunnel Roblox Proxy - END
";
        let expected = "127.0.0.1 localhost\n";
        assert_eq!(remove_marker_block(input), expected);
    }

    #[test]
    fn remove_marker_block_only_markers() {
        let input = "\
# SwiftTunnel Roblox Proxy - START
127.66.0.1 clientsettings.roblox.com
# SwiftTunnel Roblox Proxy - END
";
        assert_eq!(remove_marker_block(input), "");
    }

    #[test]
    fn domain_list_is_not_empty() {
        assert!(ROBLOX_DOMAINS.len() >= 10);
    }

    #[test]
    fn domain_list_contains_critical_entries() {
        assert!(ROBLOX_DOMAINS.contains(&"clientsettings.roblox.com"));
        assert!(ROBLOX_DOMAINS.contains(&"clientsettingscdn.roblox.com"));
        assert!(ROBLOX_DOMAINS.contains(&"setup.rbxcdn.com"));
    }
}
