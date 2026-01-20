//! Update marker module - tracks update installation state to prevent loops
//!
//! Uses a marker file to track:
//! - Target version being installed
//! - Number of installation attempts
//! - Timestamp to expire stale markers

use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Marker file name
const MARKER_FILENAME: &str = "update_marker.json";

/// Maximum installation attempts before giving up
const MAX_ATTEMPTS: u32 = 3;

/// Marker expiry time in seconds (5 minutes)
const MARKER_EXPIRY_SECS: u64 = 300;

/// Update marker stored on disk
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpdateMarker {
    /// Version being installed
    pub target_version: String,
    /// Unix timestamp when marker was created
    pub created_at: u64,
    /// Number of installation attempts
    pub attempt_count: u32,
}

/// Result of checking whether to skip update
pub enum SkipReason {
    /// Successfully updated to target version
    SuccessfulUpdate(String),
    /// Given up after max attempts
    MaxAttemptsReached(String, u32),
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkipReason::SuccessfulUpdate(v) => {
                write!(f, "Successfully updated to v{}", v)
            }
            SkipReason::MaxAttemptsReached(v, attempts) => {
                write!(f, "Gave up updating to v{} after {} attempts", v, attempts)
            }
        }
    }
}

/// Get the marker file path
fn get_marker_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("SwiftTunnel").join(MARKER_FILENAME))
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write a marker before starting installation
pub fn write_marker(target_version: &str) -> Result<(), String> {
    let path = get_marker_path().ok_or("Failed to get marker path")?;

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create marker directory: {}", e))?;
    }

    // Read existing marker to preserve attempt count
    let attempt_count = if let Some(existing) = read_marker() {
        if existing.target_version == target_version {
            // Same version, increment attempt count
            existing.attempt_count + 1
        } else {
            // Different version, reset to 1
            1
        }
    } else {
        1
    };

    let marker = UpdateMarker {
        target_version: target_version.to_string(),
        created_at: current_timestamp(),
        attempt_count,
    };

    let json = serde_json::to_string_pretty(&marker)
        .map_err(|e| format!("Failed to serialize marker: {}", e))?;

    fs::write(&path, json).map_err(|e| format!("Failed to write marker file: {}", e))?;

    info!(
        "Update marker written: version={}, attempt={}",
        target_version, attempt_count
    );

    Ok(())
}

/// Read an existing marker if present
pub fn read_marker() -> Option<UpdateMarker> {
    let path = get_marker_path()?;

    if !path.exists() {
        return None;
    }

    let content = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Delete the marker file
pub fn delete_marker() {
    if let Some(path) = get_marker_path() {
        if path.exists() {
            if let Err(e) = fs::remove_file(&path) {
                warn!("Failed to delete update marker: {}", e);
            } else {
                info!("Update marker deleted");
            }
        }
    }
}

/// Check if we should skip the update check
///
/// Returns Some(reason) if update check should be skipped, None if it should proceed
pub fn should_skip_update_check(current_version: &str) -> Option<SkipReason> {
    let marker = read_marker()?;

    let now = current_timestamp();
    let marker_age = now.saturating_sub(marker.created_at);

    // Check if marker is expired (stale marker from crash/interrupted update)
    if marker_age > MARKER_EXPIRY_SECS {
        info!(
            "Update marker expired (age: {}s), allowing update check",
            marker_age
        );
        delete_marker();
        return None;
    }

    // Check if we successfully updated to the target version
    if current_version == marker.target_version {
        info!(
            "Successfully updated to v{}, clearing marker",
            marker.target_version
        );
        delete_marker();
        return Some(SkipReason::SuccessfulUpdate(marker.target_version));
    }

    // Check if we've exceeded max attempts
    if marker.attempt_count >= MAX_ATTEMPTS {
        warn!(
            "Max update attempts ({}) reached for v{}, giving up",
            MAX_ATTEMPTS, marker.target_version
        );
        delete_marker();
        return Some(SkipReason::MaxAttemptsReached(
            marker.target_version,
            marker.attempt_count,
        ));
    }

    // Allow retry - marker will be updated with incremented attempt count
    info!(
        "Update attempt {} of {} for v{}",
        marker.attempt_count + 1,
        MAX_ATTEMPTS,
        marker.target_version
    );
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    // Use mutex to prevent test interference
    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    fn cleanup_marker() {
        if let Some(path) = get_marker_path() {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn test_write_and_read_marker() {
        let _lock = TEST_MUTEX.lock().unwrap();
        cleanup_marker();

        write_marker("1.0.0").unwrap();
        let marker = read_marker().unwrap();

        assert_eq!(marker.target_version, "1.0.0");
        assert_eq!(marker.attempt_count, 1);

        cleanup_marker();
    }

    #[test]
    fn test_attempt_count_increments() {
        let _lock = TEST_MUTEX.lock().unwrap();
        cleanup_marker();

        write_marker("1.0.0").unwrap();
        write_marker("1.0.0").unwrap();
        write_marker("1.0.0").unwrap();

        let marker = read_marker().unwrap();
        assert_eq!(marker.attempt_count, 3);

        cleanup_marker();
    }

    #[test]
    fn test_attempt_count_resets_on_new_version() {
        let _lock = TEST_MUTEX.lock().unwrap();
        cleanup_marker();

        write_marker("1.0.0").unwrap();
        write_marker("1.0.0").unwrap();
        write_marker("1.1.0").unwrap();

        let marker = read_marker().unwrap();
        assert_eq!(marker.target_version, "1.1.0");
        assert_eq!(marker.attempt_count, 1);

        cleanup_marker();
    }

    #[test]
    fn test_successful_update_detection() {
        let _lock = TEST_MUTEX.lock().unwrap();
        cleanup_marker();

        write_marker("1.0.0").unwrap();

        // Current version matches target - successful update
        let result = should_skip_update_check("1.0.0");
        assert!(matches!(result, Some(SkipReason::SuccessfulUpdate(_))));

        // Marker should be deleted
        assert!(read_marker().is_none());
    }

    #[test]
    fn test_max_attempts_reached() {
        let _lock = TEST_MUTEX.lock().unwrap();
        cleanup_marker();

        // Write marker 3 times to reach max attempts
        write_marker("1.1.0").unwrap();
        write_marker("1.1.0").unwrap();
        write_marker("1.1.0").unwrap();

        // Current version is old, but max attempts reached
        let result = should_skip_update_check("1.0.0");
        assert!(matches!(result, Some(SkipReason::MaxAttemptsReached(_, 3))));

        // Marker should be deleted
        assert!(read_marker().is_none());
    }

    #[test]
    fn test_allows_retry_under_max_attempts() {
        let _lock = TEST_MUTEX.lock().unwrap();
        cleanup_marker();

        write_marker("1.1.0").unwrap();

        // Current version is old, only 1 attempt so far
        let result = should_skip_update_check("1.0.0");
        assert!(result.is_none()); // Should allow retry

        cleanup_marker();
    }

    #[test]
    fn test_no_marker_allows_check() {
        let _lock = TEST_MUTEX.lock().unwrap();
        cleanup_marker();

        let result = should_skip_update_check("1.0.0");
        assert!(result.is_none());
    }

    #[test]
    fn test_delete_marker() {
        let _lock = TEST_MUTEX.lock().unwrap();
        cleanup_marker();

        write_marker("1.0.0").unwrap();
        assert!(read_marker().is_some());

        delete_marker();
        assert!(read_marker().is_none());
    }
}
