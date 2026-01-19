//! Types for the auto-updater module

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Current state of the update process
#[derive(Debug, Clone, PartialEq)]
pub enum UpdateState {
    /// No update activity
    Idle,
    /// Checking GitHub for updates
    Checking,
    /// Update available (not yet downloading)
    Available(UpdateInfo),
    /// Downloading update
    Downloading {
        info: UpdateInfo,
        progress: f32,
        downloaded: u64,
        total: u64,
    },
    /// Verifying checksum
    Verifying(UpdateInfo),
    /// Ready to install (downloaded and verified)
    ReadyToInstall {
        info: UpdateInfo,
        msi_path: PathBuf,
    },
    /// Installing update
    Installing,
    /// No update available (already on latest)
    UpToDate,
    /// Update check or download failed
    Failed(String),
}

impl UpdateState {
    /// Returns true if an update is available or ready
    pub fn has_update(&self) -> bool {
        matches!(
            self,
            UpdateState::Available(_)
                | UpdateState::Downloading { .. }
                | UpdateState::Verifying(_)
                | UpdateState::ReadyToInstall { .. }
        )
    }

    /// Returns true if currently downloading
    pub fn is_downloading(&self) -> bool {
        matches!(self, UpdateState::Downloading { .. })
    }

    /// Returns the update info if available
    pub fn get_info(&self) -> Option<&UpdateInfo> {
        match self {
            UpdateState::Available(info)
            | UpdateState::Downloading { info, .. }
            | UpdateState::Verifying(info)
            | UpdateState::ReadyToInstall { info, .. } => Some(info),
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
    /// New version (e.g., "0.3.1")
    pub version: String,
    /// Download URL for the MSI
    pub download_url: String,
    /// Size in bytes
    pub size: u64,
    /// SHA256 checksum URL
    pub checksum_url: Option<String>,
    /// Release notes (optional)
    pub release_notes: Option<String>,
    /// Release date
    pub published_at: Option<String>,
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

/// GitHub Release API response structure
#[derive(Debug, Deserialize)]
pub struct GithubRelease {
    pub tag_name: String,
    pub name: Option<String>,
    pub body: Option<String>,
    pub published_at: Option<String>,
    pub assets: Vec<GithubAsset>,
}

/// GitHub Release Asset structure
#[derive(Debug, Deserialize)]
pub struct GithubAsset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
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
            download_url: "https://example.com".to_string(),
            size: 1000,
            checksum_url: None,
            release_notes: None,
            published_at: None,
        };

        assert!(UpdateState::Available(info.clone()).has_update());
        assert!(UpdateState::Downloading {
            info: info.clone(),
            progress: 0.5,
            downloaded: 500,
            total: 1000
        }
        .has_update());
    }

    #[test]
    fn test_default_settings() {
        let settings = UpdateSettings::default();
        assert!(settings.auto_check);
        assert!(settings.last_check.is_none());
        assert!(settings.dismissed_version.is_none());
    }
}
