//! Update checker - fetches GitHub releases and compares versions

use super::types::{GithubRelease, UpdateInfo};
use crate::with_retry;
use log::{debug, error, info};
use semver::Version;
use std::time::Duration;

/// GitHub repository for SwiftTunnel releases
const GITHUB_REPO: &str = "Swift-tunnel/swifttunnel-app";

/// Expected MSI asset name pattern
const MSI_PATTERN: &str = "SwiftTunnel";
const MSI_EXTENSION: &str = ".msi";
const CHECKSUM_EXTENSION: &str = ".sha256";

/// Update checker that queries GitHub releases API
pub struct UpdateChecker {
    client: reqwest::Client,
    current_version: Version,
}

impl UpdateChecker {
    /// Create a new update checker with the current app version
    /// Returns None if the version string cannot be parsed (prevents update loops)
    pub fn new() -> Option<Self> {
        let version_str = env!("CARGO_PKG_VERSION");
        let current_version = match Version::parse(version_str) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to parse current version '{}': {}. Disabling update checks to prevent loops.", version_str, e);
                return None;
            }
        };

        Some(Self {
            client: reqwest::Client::builder()
                .user_agent("SwiftTunnel-Updater")
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            current_version,
        })
    }

    /// Check for updates with a timeout
    ///
    /// This is useful for startup checks where we don't want to block the app
    /// launch for too long. If the timeout expires, returns an error.
    ///
    /// # Arguments
    /// * `timeout` - Maximum time to wait for the update check
    ///
    /// # Returns
    /// * `Ok(Some(UpdateInfo))` - Update is available
    /// * `Ok(None)` - Already on latest version
    /// * `Err(String)` - Check failed or timed out
    pub async fn check_for_update_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Option<UpdateInfo>, String> {
        tokio::time::timeout(timeout, self.check_for_update())
            .await
            .map_err(|_| format!("Update check timed out after {:?}", timeout))?
    }

    /// Check for updates from GitHub releases
    /// Returns UpdateInfo if a newer version is available, None if up-to-date
    ///
    /// Uses retry logic with exponential backoff (3 attempts: 1s, 2s, 4s delays)
    pub async fn check_for_update(&self) -> Result<Option<UpdateInfo>, String> {
        let url = format!(
            "https://api.github.com/repos/{}/releases/latest",
            GITHUB_REPO
        );

        info!("Checking for updates at {}", url);

        // Use retry logic for the network request
        let release = with_retry(3, || async {
            let response = self
                .client
                .get(&url)
                .header("Accept", "application/vnd.github.v3+json")
                .send()
                .await
                .map_err(|e| format!("Network error: {}", e))?;

            // Handle rate limiting (don't retry)
            if response.status() == reqwest::StatusCode::FORBIDDEN {
                let remaining = response
                    .headers()
                    .get("x-ratelimit-remaining")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("unknown");
                return Err(format!("GitHub API rate limited. Remaining: {}", remaining));
            }

            // Handle 404 (no releases yet - don't retry, it's not an error)
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                debug!("No releases found on GitHub");
                return Ok(None);
            }

            if !response.status().is_success() {
                return Err(format!("GitHub API error: {}", response.status()));
            }

            let release: GithubRelease = response
                .json()
                .await
                .map_err(|e| format!("Failed to parse release info: {}", e))?;

            Ok(Some(release))
        })
        .await?;

        // If no release found (404), return None
        let release = match release {
            Some(r) => r,
            None => return Ok(None),
        };

        self.process_release(release)
    }

    /// Process the GitHub release and determine if it's newer
    fn process_release(&self, release: GithubRelease) -> Result<Option<UpdateInfo>, String> {
        // Parse version from tag (e.g., "v0.3.1" -> "0.3.1")
        let tag = release.tag_name.trim_start_matches('v');
        let remote_version = Version::parse(tag).map_err(|e| {
            format!("Invalid version tag '{}': {}", release.tag_name, e)
        })?;

        info!(
            "Current version: {}, Latest release: {}",
            self.current_version, remote_version
        );

        // Check if remote is newer
        if remote_version <= self.current_version {
            info!("Already on latest version");
            return Ok(None);
        }

        // Find MSI asset
        let msi_asset = release
            .assets
            .iter()
            .find(|a| a.name.starts_with(MSI_PATTERN) && a.name.ends_with(MSI_EXTENSION));

        let msi_asset = match msi_asset {
            Some(asset) => asset,
            None => {
                error!("No MSI asset found in release");
                return Err("Release has no Windows installer".to_string());
            }
        };

        // Find checksum asset (optional)
        let checksum_url = release
            .assets
            .iter()
            .find(|a| a.name == format!("{}{}", msi_asset.name, CHECKSUM_EXTENSION))
            .map(|a| a.browser_download_url.clone());

        info!(
            "Update available: {} -> {} ({})",
            self.current_version, remote_version, msi_asset.name
        );

        Ok(Some(UpdateInfo {
            version: remote_version.to_string(),
            download_url: msi_asset.browser_download_url.clone(),
            size: msi_asset.size,
            checksum_url,
            release_notes: release.body,
            published_at: release.published_at,
        }))
    }

    /// Get the current version string
    pub fn current_version(&self) -> &str {
        // Return the string representation
        // Note: We need to store this separately since Version doesn't impl Display as &str
        env!("CARGO_PKG_VERSION")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        let checker = UpdateChecker::new();
        // Should return Some since CARGO_PKG_VERSION should be valid
        assert!(checker.is_some());
        let checker = checker.unwrap();
        let _ = checker.current_version();
    }

    #[test]
    fn test_semver_comparison() {
        let v1 = Version::parse("0.3.0").unwrap();
        let v2 = Version::parse("0.3.1").unwrap();
        let v3 = Version::parse("0.2.9").unwrap();

        assert!(v2 > v1);
        assert!(v1 > v3);
        assert!(v3 < v1);
    }
}
