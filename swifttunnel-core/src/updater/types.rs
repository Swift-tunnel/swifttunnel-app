//! Types for the auto-updater module

use serde::{Deserialize, Serialize};
use std::fmt;

/// User-selected update channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum UpdateChannel {
    Live,
    #[default]
    Stable,
}

impl UpdateChannel {
    /// Lowercase channel class used for release classification/manifests.
    pub fn channel_class(&self) -> &'static str {
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
    fn test_default_settings() {
        let settings = UpdateSettings::default();
        assert!(settings.auto_check);
        assert!(settings.last_check.is_none());
        assert!(settings.dismissed_version.is_none());
    }

    #[test]
    fn test_update_channel_defaults_to_stable() {
        assert_eq!(UpdateChannel::default(), UpdateChannel::Stable);
        assert_eq!(UpdateChannel::Stable.channel_class(), "stable");
        assert_eq!(UpdateChannel::Live.channel_class(), "live");
    }
}
