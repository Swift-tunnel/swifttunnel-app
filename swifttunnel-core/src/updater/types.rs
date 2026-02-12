//! Types for the auto-updater module

use serde::{Deserialize, Serialize};
use std::fmt;

/// Current state of the update process
#[derive(Debug, Clone, PartialEq)]
pub enum UpdateState {
    /// No update activity
    Idle,
    /// Checking for updates
    Checking,
    /// Update available
    Available(UpdateInfo),
    /// Downloading update
    Downloading { info: UpdateInfo, progress: f32 },
    /// No update available (already on latest)
    UpToDate,
    /// Update check or download failed
    Failed(String),
}

impl UpdateState {
    /// Returns true if an update is available or downloading
    pub fn has_update(&self) -> bool {
        matches!(
            self,
            UpdateState::Available(_) | UpdateState::Downloading { .. }
        )
    }

    /// Returns true if currently downloading
    pub fn is_downloading(&self) -> bool {
        matches!(self, UpdateState::Downloading { .. })
    }

    /// Returns the update info if available
    pub fn get_info(&self) -> Option<&UpdateInfo> {
        match self {
            UpdateState::Available(info) | UpdateState::Downloading { info, .. } => Some(info),
            _ => None,
        }
    }

    /// Returns download progress (0.0-1.0) if downloading
    pub fn download_progress(&self) -> Option<f32> {
        match self {
            UpdateState::Downloading { progress, .. } => Some(*progress),
            _ => None,
        }
    }
}

/// Information about an available update
#[derive(Debug, Clone, PartialEq)]
pub struct UpdateInfo {
    /// New version string
    pub version: String,
}

/// User-selected update channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateChannel {
    Live,
    Stable,
}

impl UpdateChannel {
    /// Channel name used by Velopack feeds (`releases.<channel>.json`).
    pub fn velopack_channel(&self) -> &'static str {
        match self {
            UpdateChannel::Live => "live",
            UpdateChannel::Stable => "stable",
        }
    }
}

impl fmt::Display for UpdateChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateChannel::Live => write!(f, "Live"),
            UpdateChannel::Stable => write!(f, "Stable"),
        }
    }
}

impl Default for UpdateChannel {
    fn default() -> Self {
        Self::Stable
    }
}

/// User settings for auto-updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSettings {
    /// Check for updates automatically on startup
    #[serde(default = "default_auto_check")]
    pub auto_check: bool,
    /// Last time we checked for updates (Unix timestamp)
    #[serde(default)]
    pub last_check: Option<i64>,
    /// Version that user dismissed (won't show banner for this version)
    #[serde(default)]
    pub dismissed_version: Option<String>,
}

fn default_auto_check() -> bool {
    true
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            auto_check: true,
            last_check: None,
            dismissed_version: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_state_has_update() {
        assert!(!UpdateState::Idle.has_update());
        assert!(!UpdateState::Checking.has_update());
        assert!(!UpdateState::UpToDate.has_update());
        assert!(!UpdateState::Failed("test".to_string()).has_update());

        let info = UpdateInfo {
            version: "0.3.1".to_string(),
        };

        assert!(UpdateState::Available(info.clone()).has_update());
        assert!(
            UpdateState::Downloading {
                info: info.clone(),
                progress: 0.5,
            }
            .has_update()
        );
    }

    #[test]
    fn test_default_settings() {
        let settings = UpdateSettings::default();
        assert!(settings.auto_check);
        assert!(settings.last_check.is_none());
        assert!(settings.dismissed_version.is_none());
    }

    #[test]
    fn test_update_channel_defaults_to_stable() {
        assert_eq!(UpdateChannel::default(), UpdateChannel::Stable);
        assert_eq!(UpdateChannel::Stable.velopack_channel(), "stable");
        assert_eq!(UpdateChannel::Live.velopack_channel(), "live");
    }
}
