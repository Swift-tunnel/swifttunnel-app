//! Velopack-based auto-updater
//!
//! Checks for updates from GitHub Releases API and then uses Velopack for
//! download/apply.
//! Falls back gracefully when not installed via Velopack (dev/debug builds).

use super::types::{UpdateChannel, UpdateInfo, UpdateState};
use log::{error, info, warn};
use semver::Version;
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// GitHub repo path for constructing release download URLs
const GITHUB_REPO: &str = "Swift-tunnel/swifttunnel-app";
const GITHUB_RELEASES_API_URL: &str =
    "https://api.github.com/repos/Swift-tunnel/swifttunnel-app/releases";
const UPDATE_HTTP_USER_AGENT: &str = "SwiftTunnel-Updater";

/// Build a direct download URL for a specific release version's assets.
/// This avoids GitHub's /releases/latest/download redirect which can point
/// to the wrong release when drafts are published out of order.
fn releases_url_for_version(version: &Version) -> String {
    format!(
        "https://github.com/{}/releases/download/v{version}",
        GITHUB_REPO
    )
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    prerelease: bool,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
}

/// Result of the auto-update check
#[derive(Clone)]
pub enum AutoUpdateResult {
    NoUpdate,
    UpdateInstalled,
    Failed(String),
    Skipped,
}

/// Run the auto-updater at startup
///
/// With Velopack, pending updates are applied automatically by VelopackApp::build().run()
/// in main(). This function just checks for NEW updates in the background.
/// No splash screen needed - the check is fast and non-blocking.
pub fn run_auto_updater(channel: UpdateChannel) -> AutoUpdateResult {
    info!("Checking for updates via Velopack ({})...", channel);

    let expected_version = match find_latest_newer_version(channel) {
        Ok(Some(version)) => version,
        Ok(None) => {
            info!("No newer eligible {} release found on GitHub API", channel);
            return AutoUpdateResult::NoUpdate;
        }
        Err(e) => {
            warn!("Failed to query GitHub releases API (ignored): {}", e);
            return AutoUpdateResult::NoUpdate;
        }
    };

    // Try to create UpdateManager - will fail if not installed via Velopack
    let um = match create_update_manager(channel, &expected_version) {
        Some(um) => um,
        None => {
            info!("Not installed via Velopack (dev mode), skipping update check");
            return AutoUpdateResult::Skipped;
        }
    };

    // Check feed with Velopack and make sure it matches channel-filtered API result
    match um.check_for_updates() {
        Ok(velopack::UpdateCheck::UpdateAvailable(update)) => {
            let version = update.TargetFullRelease.Version.to_string();
            let parsed = Version::parse(&version).ok();
            if parsed.as_ref() != Some(&expected_version) {
                warn!(
                    "Ignoring Velopack update {} because latest eligible {} release is {}",
                    version, channel, expected_version
                );
                return AutoUpdateResult::NoUpdate;
            }
            info!("Update available: v{} ({})", version, channel);

            // Download and apply immediately at startup
            info!("Downloading update...");
            match um.download_updates(&update, None) {
                Ok(()) => {
                    info!("Update downloaded, applying and restarting...");
                    match um.apply_updates_and_restart(&update) {
                        Ok(()) => {
                            // This line should not be reached - process restarts
                            AutoUpdateResult::UpdateInstalled
                        }
                        Err(e) => {
                            error!("Failed to apply update: {}", e);
                            AutoUpdateResult::Failed(format!("Failed to apply update: {}", e))
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to download update: {}", e);
                    AutoUpdateResult::Failed(format!("Download failed: {}", e))
                }
            }
        }
        Ok(velopack::UpdateCheck::NoUpdateAvailable) => {
            info!("Already on latest version");
            AutoUpdateResult::NoUpdate
        }
        Ok(velopack::UpdateCheck::RemoteIsEmpty) => {
            info!("No releases found");
            AutoUpdateResult::NoUpdate
        }
        Err(e) => {
            // Don't treat network errors as failures - just skip silently
            // (no releases uploaded yet, offline, GitHub down, etc.)
            warn!("Update check failed (ignored): {}", e);
            AutoUpdateResult::NoUpdate
        }
    }
}

/// Create a Velopack UpdateManager, returning None if not installed via Velopack.
/// Uses a direct URL to the target version's release assets to avoid GitHub's
/// /releases/latest redirect pointing to the wrong release.
///
/// Channel filtering is handled upstream by the GitHub API query (stable skips
/// prereleases, live includes them), so we don't set ExplicitChannel here —
/// letting Velopack use its default platform channel ("win") which matches the
/// `releases.win.json` produced by `vpk pack`.
fn create_update_manager(
    _channel: UpdateChannel,
    target_version: &Version,
) -> Option<velopack::UpdateManager> {
    let url = releases_url_for_version(target_version);
    let source = velopack::sources::HttpSource::new(&url);
    match velopack::UpdateManager::new(source, None, None) {
        Ok(um) => Some(um),
        Err(e) => {
            info!(
                "Velopack UpdateManager unavailable: {} (expected in dev mode)",
                e
            );
            None
        }
    }
}

fn parse_release_version(tag_name: &str) -> Option<Version> {
    let trimmed = tag_name.trim();
    let normalized = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    Version::parse(normalized).ok()
}

fn has_velopack_assets(release: &GitHubRelease) -> bool {
    let has_feed = release
        .assets
        .iter()
        .any(|asset| asset.name.eq_ignore_ascii_case("releases.win.json"));
    let has_package = release
        .assets
        .iter()
        .any(|asset| asset.name.ends_with(".nupkg"));

    has_feed && has_package
}

fn fetch_latest_eligible_release_version(
    channel: UpdateChannel,
) -> Result<Option<Version>, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to create runtime for update API call: {}", e))?;

    runtime.block_on(async move {
        let client = reqwest::Client::builder()
            .user_agent(UPDATE_HTTP_USER_AGENT)
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

        let response = client
            .get(GITHUB_RELEASES_API_URL)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch GitHub releases: {}", e))?;

        if !response.status().is_success() {
            return Err(format!(
                "GitHub releases API returned HTTP {}",
                response.status()
            ));
        }

        let releases: Vec<GitHubRelease> = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse GitHub releases JSON: {}", e))?;

        let mut latest: Option<Version> = None;
        for release in releases {
            if release.draft {
                continue;
            }
            if channel == UpdateChannel::Stable && release.prerelease {
                continue;
            }
            if !has_velopack_assets(&release) {
                continue;
            }
            let Some(version) = parse_release_version(&release.tag_name) else {
                continue;
            };
            if latest.as_ref().map(|v| version > *v).unwrap_or(true) {
                latest = Some(version);
            }
        }

        Ok(latest)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_velopack_assets_requires_feed_and_package() {
        let good = GitHubRelease {
            tag_name: "v1.0.40".to_string(),
            prerelease: false,
            draft: false,
            assets: vec![
                GitHubAsset {
                    name: "releases.win.json".to_string(),
                },
                GitHubAsset {
                    name: "SwiftTunnel-1.0.40-full.nupkg".to_string(),
                },
            ],
        };
        assert!(has_velopack_assets(&good));

        let missing_feed = GitHubRelease {
            tag_name: "v1.0.42".to_string(),
            prerelease: true,
            draft: false,
            assets: vec![GitHubAsset {
                name: "latest.json".to_string(),
            }],
        };
        assert!(!has_velopack_assets(&missing_feed));

        let missing_pkg = GitHubRelease {
            tag_name: "v1.0.43".to_string(),
            prerelease: true,
            draft: false,
            assets: vec![GitHubAsset {
                name: "releases.win.json".to_string(),
            }],
        };
        assert!(!has_velopack_assets(&missing_pkg));
    }
}

fn find_latest_newer_version(channel: UpdateChannel) -> Result<Option<Version>, String> {
    let current_version = Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|e| format!("Failed to parse current app version: {}", e))?;

    let latest_eligible = fetch_latest_eligible_release_version(channel)?;
    Ok(latest_eligible.filter(|v| v > &current_version))
}

/// Check for updates in the background and update shared state
/// Used by the GUI for manual update checks
pub fn check_for_updates_background(update_state: Arc<Mutex<UpdateState>>, channel: UpdateChannel) {
    std::thread::spawn(move || {
        let expected_version = match find_latest_newer_version(channel) {
            Ok(Some(version)) => version,
            Ok(None) => {
                if let Ok(mut state) = update_state.lock() {
                    *state = UpdateState::UpToDate;
                }
                return;
            }
            Err(e) => {
                warn!("Background GitHub release check failed (ignored): {}", e);
                if let Ok(mut state) = update_state.lock() {
                    *state = UpdateState::UpToDate;
                }
                return;
            }
        };

        let um = match create_update_manager(channel, &expected_version) {
            Some(um) => um,
            None => {
                // Not installed via Velopack (dev mode) — stay idle, no error
                return;
            }
        };

        match um.check_for_updates() {
            Ok(velopack::UpdateCheck::UpdateAvailable(update)) => {
                let version = update.TargetFullRelease.Version.to_string();
                let parsed = Version::parse(&version).ok();
                if parsed.as_ref() == Some(&expected_version) {
                    info!("Update available: v{} ({})", version, channel);
                    if let Ok(mut state) = update_state.lock() {
                        *state = UpdateState::Available(UpdateInfo { version });
                    }
                } else {
                    warn!(
                        "Ignoring Velopack update {} because latest eligible {} release is {}",
                        version, channel, expected_version
                    );
                    if let Ok(mut state) = update_state.lock() {
                        *state = UpdateState::UpToDate;
                    }
                }
            }
            Ok(_) => {
                info!("No matching Velopack update available for {}", channel);
                if let Ok(mut state) = update_state.lock() {
                    *state = UpdateState::UpToDate;
                }
            }
            Err(e) => {
                // Network errors (404, offline, etc.) are not user-visible failures
                // Just log and stay idle - no error banner
                warn!("Background update check failed (ignored): {}", e);
                if let Ok(mut state) = update_state.lock() {
                    *state = UpdateState::UpToDate;
                }
            }
        }
    });
}

/// Download and apply an update in the background
/// Updates shared state with progress
pub fn download_and_apply_update(
    update_state: Arc<Mutex<UpdateState>>,
    version: String,
    channel: UpdateChannel,
) {
    std::thread::spawn(move || {
        let expected_version = match Version::parse(&version) {
            Ok(v) => v,
            Err(e) => {
                if let Ok(mut state) = update_state.lock() {
                    *state =
                        UpdateState::Failed(format!("Invalid update version '{}': {}", version, e));
                }
                return;
            }
        };

        let um = match create_update_manager(channel, &expected_version) {
            Some(um) => um,
            None => {
                // Not installed via Velopack — silently reset to idle
                if let Ok(mut state) = update_state.lock() {
                    *state = UpdateState::Idle;
                }
                return;
            }
        };

        // Re-check to get the update info and confirm it matches requested version
        let update = match um.check_for_updates() {
            Ok(velopack::UpdateCheck::UpdateAvailable(u)) => {
                let available_version = Version::parse(&u.TargetFullRelease.Version).ok();
                if available_version.as_ref() != Some(&expected_version) {
                    if let Ok(mut state) = update_state.lock() {
                        *state = UpdateState::Failed(format!(
                            "Requested version {} is no longer available on {} channel",
                            expected_version, channel
                        ));
                    }
                    return;
                }
                u
            }
            _ => {
                if let Ok(mut state) = update_state.lock() {
                    *state = UpdateState::Failed("Update no longer available".to_string());
                }
                return;
            }
        };

        let info = UpdateInfo {
            version: expected_version.to_string(),
        };

        // Set downloading state
        if let Ok(mut state) = update_state.lock() {
            *state = UpdateState::Downloading {
                info: info.clone(),
                progress: 0.0,
            };
        }

        // Create progress channel
        let (tx, rx) = std::sync::mpsc::channel::<i16>();
        let progress_state = Arc::clone(&update_state);
        let progress_info = info.clone();

        // Spawn progress monitor thread
        let progress_thread = std::thread::spawn(move || {
            while let Ok(pct) = rx.recv() {
                let progress = pct as f32 / 100.0;
                if let Ok(mut state) = progress_state.lock() {
                    *state = UpdateState::Downloading {
                        info: progress_info.clone(),
                        progress,
                    };
                }
            }
        });

        // Download using Velopack's sync Sender wrapper
        // Note: Velopack uses std::sync::mpsc::Sender<i16> for progress
        match um.download_updates(&update, Some(tx)) {
            Ok(()) => {
                // Wait for progress thread to finish
                let _ = progress_thread.join();

                info!("Update downloaded, applying and restarting...");
                match um.apply_updates_and_restart(&update) {
                    Ok(()) => {
                        // Process should restart - this line shouldn't be reached
                    }
                    Err(e) => {
                        error!("Failed to apply update: {}", e);
                        if let Ok(mut state) = update_state.lock() {
                            *state = UpdateState::Failed(format!("Failed to apply: {}", e));
                        }
                    }
                }
            }
            Err(e) => {
                error!("Download failed: {}", e);
                let _ = progress_thread.join();
                if let Ok(mut state) = update_state.lock() {
                    *state = UpdateState::Failed(format!("Download failed: {}", e));
                }
            }
        }
    });
}
