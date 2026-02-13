use base64::Engine as _;
use reqwest::header::{ACCEPT, USER_AGENT};
use ring::signature::{ED25519, UnparsedPublicKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::AppHandle;
use tauri_plugin_updater::UpdaterExt;
use url::Url;

use swifttunnel_core::updater::UpdateChannel;

const GITHUB_RELEASES_API_URL: &str =
    "https://api.github.com/repos/Swift-tunnel/swifttunnel-app/releases";
const GITHUB_RELEASES_DOWNLOAD_BASE_URL: &str =
    "https://github.com/Swift-tunnel/swifttunnel-app/releases/download";
const GITHUB_API_ACCEPT: &str = "application/vnd.github+json";
const GITHUB_API_USER_AGENT: &str = "SwiftTunnel-Updater";
const UPDATE_MANIFEST_FILE_NAME: &str = "swifttunnel-update-manifest.json";
const UPDATE_MANIFEST_SIGNATURE_FILE_NAME: &str = "swifttunnel-update-manifest.sig";
const UPDATE_MANIFEST_PUBLIC_KEY_PLACEHOLDER: &str =
    "REPLACE_WITH_SWIFTTUNNEL_UPDATE_MANIFEST_PUBLIC_KEY_B64";

#[derive(Debug, Serialize)]
pub struct UpdaterCheckResponse {
    pub current_version: String,
    pub available_version: Option<String>,
    pub release_tag: Option<String>,
    pub channel: String,
}

#[derive(Debug, Serialize)]
pub struct UpdaterInstallResponse {
    pub installed_version: String,
    pub release_tag: String,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
}

#[derive(Debug, Deserialize)]
struct SignedUpdateManifest {
    version: String,
    tag: String,
    channel_class: String,
    latest_json_url: String,
    latest_json_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectedRelease {
    tag_name: String,
    version: Version,
    prerelease: bool,
}

#[derive(Debug)]
struct PreparedUpdate {
    selected_release: SelectedRelease,
    manifest: SignedUpdateManifest,
}

fn update_manifest_public_key_b64() -> Result<String, String> {
    let runtime_key = std::env::var("SWIFTTUNNEL_UPDATE_MANIFEST_PUBLIC_KEY_B64")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let key = runtime_key.unwrap_or_else(|| {
        option_env!("SWIFTTUNNEL_UPDATE_MANIFEST_PUBLIC_KEY_B64")
            .unwrap_or(UPDATE_MANIFEST_PUBLIC_KEY_PLACEHOLDER)
            .trim()
            .to_string()
    });
    if key.is_empty() || key == UPDATE_MANIFEST_PUBLIC_KEY_PLACEHOLDER {
        return Err("Updater manifest public key is not configured".to_string());
    }
    Ok(key)
}

fn channel_name(channel: UpdateChannel) -> &'static str {
    match channel {
        UpdateChannel::Live => "Live",
        UpdateChannel::Stable => "Stable",
    }
}

fn release_class(prerelease: bool) -> &'static str {
    if prerelease { "live" } else { "stable" }
}

fn normalize_tag_version(tag_name: &str) -> Option<Version> {
    let trimmed = tag_name.trim();
    let candidate = trimmed.strip_prefix('v').unwrap_or(trimmed);
    Version::parse(candidate).ok()
}

fn normalize_sha256(value: &str) -> String {
    let trimmed = value.trim();
    let without_prefix = if trimmed.len() >= 7 && trimmed[..7].eq_ignore_ascii_case("sha256:") {
        &trimmed[7..]
    } else {
        trimmed
    };
    without_prefix.to_ascii_lowercase()
}

fn latest_json_url_for_tag(tag_name: &str) -> String {
    format!("{GITHUB_RELEASES_DOWNLOAD_BASE_URL}/{tag_name}/latest.json")
}

fn manifest_url_for_tag(tag_name: &str) -> String {
    format!("{GITHUB_RELEASES_DOWNLOAD_BASE_URL}/{tag_name}/{UPDATE_MANIFEST_FILE_NAME}")
}

fn manifest_signature_url_for_tag(tag_name: &str) -> String {
    format!("{GITHUB_RELEASES_DOWNLOAD_BASE_URL}/{tag_name}/{UPDATE_MANIFEST_SIGNATURE_FILE_NAME}")
}

fn select_release_for_channel(
    releases: Vec<GithubRelease>,
    channel: UpdateChannel,
    current_version: &Version,
) -> Option<SelectedRelease> {
    releases
        .into_iter()
        .filter(|release| !release.draft)
        .filter(|release| channel == UpdateChannel::Live || !release.prerelease)
        .filter_map(|release| {
            let version = normalize_tag_version(&release.tag_name)?;
            Some(SelectedRelease {
                tag_name: release.tag_name,
                version,
                prerelease: release.prerelease,
            })
        })
        .filter(|release| release.version > *current_version)
        .max_by(|left, right| left.version.cmp(&right.version))
}

fn verify_manifest_signature(manifest_bytes: &[u8], signature_b64: &str) -> Result<(), String> {
    let public_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(update_manifest_public_key_b64()?)
        .map_err(|e| format!("Invalid updater manifest public key encoding: {}", e))?;
    verify_manifest_signature_with_public_key(manifest_bytes, signature_b64, &public_key_bytes)
}

fn verify_manifest_signature_with_public_key(
    manifest_bytes: &[u8],
    signature_b64: &str,
    public_key_bytes: &[u8],
) -> Result<(), String> {
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.trim())
        .map_err(|e| format!("Invalid updater manifest signature encoding: {}", e))?;

    UnparsedPublicKey::new(&ED25519, &public_key_bytes)
        .verify(manifest_bytes, &signature_bytes)
        .map_err(|e| format!("Updater manifest signature verification failed: {}", e))
}

fn verify_bytes_sha256(bytes: &[u8], expected_sha256: &str) -> Result<(), String> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let actual_hash = format!("{:x}", hasher.finalize());
    let expected_hash = normalize_sha256(expected_sha256);

    if actual_hash != expected_hash {
        return Err(format!(
            "latest.json SHA256 mismatch: expected '{}', got '{}'",
            expected_hash, actual_hash
        ));
    }

    Ok(())
}

fn verify_manifest_payload(
    manifest: &SignedUpdateManifest,
    selected_release: &SelectedRelease,
    expected_latest_json_url: &str,
) -> Result<(), String> {
    if manifest.tag != selected_release.tag_name {
        return Err(format!(
            "Manifest tag mismatch: expected '{}', got '{}'",
            selected_release.tag_name, manifest.tag
        ));
    }

    let manifest_version = Version::parse(&manifest.version).map_err(|e| {
        format!(
            "Manifest contains invalid version '{}': {}",
            manifest.version, e
        )
    })?;
    if manifest_version != selected_release.version {
        return Err(format!(
            "Manifest version mismatch: expected '{}', got '{}'",
            selected_release.version, manifest.version
        ));
    }

    if !manifest
        .channel_class
        .eq_ignore_ascii_case(release_class(selected_release.prerelease))
    {
        return Err(format!(
            "Manifest channel mismatch: expected '{}', got '{}'",
            release_class(selected_release.prerelease),
            manifest.channel_class
        ));
    }

    if manifest.latest_json_url != expected_latest_json_url {
        return Err(format!(
            "Manifest latest.json URL mismatch: expected '{}', got '{}'",
            expected_latest_json_url, manifest.latest_json_url
        ));
    }

    Ok(())
}

async fn github_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .build()
        .map_err(|e| format!("Failed to create updater HTTP client: {}", e))
}

async fn fetch_releases(client: &reqwest::Client) -> Result<Vec<GithubRelease>, String> {
    let response = client
        .get(GITHUB_RELEASES_API_URL)
        .header(USER_AGENT, GITHUB_API_USER_AGENT)
        .header(ACCEPT, GITHUB_API_ACCEPT)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch GitHub releases: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "GitHub releases API returned status {}",
            response.status()
        ));
    }

    response
        .json::<Vec<GithubRelease>>()
        .await
        .map_err(|e| format!("Failed to parse GitHub releases: {}", e))
}

async fn fetch_manifest_with_verification(
    client: &reqwest::Client,
    selected_release: &SelectedRelease,
) -> Result<SignedUpdateManifest, String> {
    let latest_json_url = latest_json_url_for_tag(&selected_release.tag_name);
    let manifest_url = manifest_url_for_tag(&selected_release.tag_name);
    let signature_url = manifest_signature_url_for_tag(&selected_release.tag_name);

    let manifest_response = client
        .get(&manifest_url)
        .header(USER_AGENT, GITHUB_API_USER_AGENT)
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| format!("Failed to fetch updater manifest: {}", e))?;

    if !manifest_response.status().is_success() {
        return Err(format!(
            "Updater manifest endpoint returned status {}",
            manifest_response.status()
        ));
    }

    let manifest_bytes = manifest_response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read updater manifest bytes: {}", e))?;

    let signature_response = client
        .get(&signature_url)
        .header(USER_AGENT, GITHUB_API_USER_AGENT)
        .header(ACCEPT, "text/plain")
        .send()
        .await
        .map_err(|e| format!("Failed to fetch updater manifest signature: {}", e))?;

    if !signature_response.status().is_success() {
        return Err(format!(
            "Updater manifest signature endpoint returned status {}",
            signature_response.status()
        ));
    }

    let signature_b64 = signature_response
        .text()
        .await
        .map_err(|e| format!("Failed to read updater manifest signature: {}", e))?;

    verify_manifest_signature(&manifest_bytes, &signature_b64)?;

    let manifest: SignedUpdateManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("Failed to parse updater manifest JSON: {}", e))?;

    verify_manifest_payload(&manifest, selected_release, &latest_json_url)?;

    Ok(manifest)
}

async fn verify_latest_json_hash(
    client: &reqwest::Client,
    manifest: &SignedUpdateManifest,
) -> Result<(), String> {
    let latest_response = client
        .get(&manifest.latest_json_url)
        .header(USER_AGENT, GITHUB_API_USER_AGENT)
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| format!("Failed to fetch release latest.json: {}", e))?;

    if !latest_response.status().is_success() {
        return Err(format!(
            "latest.json endpoint returned status {}",
            latest_response.status()
        ));
    }

    let latest_json_bytes = latest_response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read latest.json bytes: {}", e))?;

    verify_bytes_sha256(&latest_json_bytes, &manifest.latest_json_sha256)
}

async fn prepare_channel_update(
    channel: UpdateChannel,
    current_version: &Version,
) -> Result<Option<PreparedUpdate>, String> {
    let client = github_client().await?;
    let releases = fetch_releases(&client).await?;

    let Some(selected_release) = select_release_for_channel(releases, channel, current_version)
    else {
        return Ok(None);
    };

    let manifest = fetch_manifest_with_verification(&client, &selected_release).await?;
    verify_latest_json_hash(&client, &manifest).await?;

    Ok(Some(PreparedUpdate {
        selected_release,
        manifest,
    }))
}

async fn check_update_for_manifest(
    app: &AppHandle,
    manifest: &SignedUpdateManifest,
) -> Result<Option<tauri_plugin_updater::Update>, String> {
    let endpoint = Url::parse(&manifest.latest_json_url)
        .map_err(|e| format!("Invalid latest.json endpoint URL: {}", e))?;

    let builder = app
        .updater_builder()
        .endpoints(vec![endpoint])
        .map_err(|e| format!("Failed to configure updater endpoint: {}", e))?;

    let updater = builder
        .build()
        .map_err(|e| format!("Failed to initialize updater: {}", e))?;

    updater
        .check()
        .await
        .map_err(|e| format!("Updater check failed: {}", e))
}

#[tauri::command]
pub async fn updater_check_channel(
    app: AppHandle,
    channel: UpdateChannel,
) -> Result<UpdaterCheckResponse, String> {
    let current_version = Version::parse(&app.package_info().version.to_string())
        .map_err(|e| format!("Current app version is invalid semver: {}", e))?;

    let Some(prepared) = prepare_channel_update(channel, &current_version).await? else {
        return Ok(UpdaterCheckResponse {
            current_version: current_version.to_string(),
            available_version: None,
            release_tag: None,
            channel: channel_name(channel).to_string(),
        });
    };

    let maybe_update = check_update_for_manifest(&app, &prepared.manifest).await?;
    let Some(update) = maybe_update else {
        return Ok(UpdaterCheckResponse {
            current_version: current_version.to_string(),
            available_version: None,
            release_tag: None,
            channel: channel_name(channel).to_string(),
        });
    };

    if update.version != prepared.selected_release.version.to_string() {
        return Err(format!(
            "Updater version mismatch: expected '{}', got '{}'",
            prepared.selected_release.version, update.version
        ));
    }

    Ok(UpdaterCheckResponse {
        current_version: update.current_version,
        available_version: Some(update.version),
        release_tag: Some(prepared.selected_release.tag_name),
        channel: channel_name(channel).to_string(),
    })
}

#[tauri::command]
pub async fn updater_install_channel(
    app: AppHandle,
    channel: UpdateChannel,
    expected_version: String,
) -> Result<UpdaterInstallResponse, String> {
    let current_version = Version::parse(&app.package_info().version.to_string())
        .map_err(|e| format!("Current app version is invalid semver: {}", e))?;
    let normalized_expected_version = Version::parse(expected_version.trim()).map_err(|e| {
        format!(
            "Expected version '{}' is invalid semver: {}",
            expected_version, e
        )
    })?;

    let Some(prepared) = prepare_channel_update(channel, &current_version).await? else {
        return Err("No eligible update found for the selected channel".to_string());
    };

    if prepared.selected_release.version != normalized_expected_version {
        return Err(format!(
            "Expected version '{}' does not match selected release '{}'",
            normalized_expected_version, prepared.selected_release.version
        ));
    }

    let maybe_update = check_update_for_manifest(&app, &prepared.manifest).await?;
    let Some(update) = maybe_update else {
        return Err("No installable update found after channel verification".to_string());
    };

    if update.version != normalized_expected_version.to_string() {
        return Err(format!(
            "Updater returned version '{}' but expected '{}'",
            update.version, normalized_expected_version
        ));
    }

    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|e| format!("Failed to download/install update: {}", e))?;

    Ok(UpdaterInstallResponse {
        installed_version: update.version,
        release_tag: prepared.selected_release.tag_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn release(tag: &str, prerelease: bool) -> GithubRelease {
        GithubRelease {
            tag_name: tag.to_string(),
            draft: false,
            prerelease,
        }
    }

    fn release_with_draft(tag: &str, prerelease: bool, draft: bool) -> GithubRelease {
        GithubRelease {
            tag_name: tag.to_string(),
            draft,
            prerelease,
        }
    }

    fn make_selected_release(tag: &str, version: &str, prerelease: bool) -> SelectedRelease {
        SelectedRelease {
            tag_name: tag.to_string(),
            version: Version::parse(version).unwrap(),
            prerelease,
        }
    }

    fn make_manifest(
        version: &str,
        tag: &str,
        channel_class: &str,
        latest_json_url: &str,
        latest_json_sha256: &str,
    ) -> SignedUpdateManifest {
        SignedUpdateManifest {
            version: version.to_string(),
            tag: tag.to_string(),
            channel_class: channel_class.to_string(),
            latest_json_url: latest_json_url.to_string(),
            latest_json_sha256: latest_json_sha256.to_string(),
        }
    }

    fn sign_payload(payload: &[u8]) -> (Vec<u8>, String) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let signature = key_pair.sign(payload);
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.as_ref());
        let public_key_bytes = key_pair.public_key().as_ref().to_vec();
        (public_key_bytes, signature_b64)
    }

    #[test]
    fn select_release_prefers_stable_for_stable_channel() {
        let current = Version::parse("1.0.0").unwrap();
        let selected = select_release_for_channel(
            vec![
                release("v1.1.0-beta.1", true),
                release("v1.1.0", false),
                release("v1.0.5", false),
            ],
            UpdateChannel::Stable,
            &current,
        )
        .unwrap();

        assert_eq!(selected.tag_name, "v1.1.0");
        assert!(!selected.prerelease);
    }

    #[test]
    fn select_release_returns_none_when_stable_has_only_prerelease() {
        let current = Version::parse("1.0.0").unwrap();
        let selected = select_release_for_channel(
            vec![release("v1.1.0-beta.1", true)],
            UpdateChannel::Stable,
            &current,
        );

        assert!(selected.is_none());
    }

    #[test]
    fn select_release_live_picks_newer_prerelease() {
        let current = Version::parse("1.0.0").unwrap();
        let selected = select_release_for_channel(
            vec![release("v1.1.0", false), release("v1.2.0-beta.1", true)],
            UpdateChannel::Live,
            &current,
        )
        .unwrap();

        assert_eq!(selected.tag_name, "v1.2.0-beta.1");
        assert!(selected.prerelease);
    }

    #[test]
    fn select_release_live_picks_stable_when_latest_is_stable() {
        let current = Version::parse("1.0.0").unwrap();
        let selected = select_release_for_channel(
            vec![release("v1.1.0-beta.2", true), release("v1.1.0", false)],
            UpdateChannel::Live,
            &current,
        )
        .unwrap();

        assert_eq!(selected.tag_name, "v1.1.0");
        assert!(!selected.prerelease);
    }

    #[test]
    fn select_release_ignores_drafts() {
        let current = Version::parse("1.0.0").unwrap();
        let selected = select_release_for_channel(
            vec![
                release_with_draft("v1.3.0", false, true),
                release_with_draft("v1.2.0", false, false),
            ],
            UpdateChannel::Stable,
            &current,
        )
        .unwrap();

        assert_eq!(selected.tag_name, "v1.2.0");
        assert_eq!(selected.version, Version::parse("1.2.0").unwrap());
    }

    #[test]
    fn select_release_returns_none_when_not_newer_than_current() {
        let current = Version::parse("1.2.0").unwrap();
        let selected = select_release_for_channel(
            vec![release("v1.2.0", false), release("v1.1.9", false)],
            UpdateChannel::Stable,
            &current,
        );

        assert!(selected.is_none());
    }

    #[test]
    fn normalize_sha256_strips_prefix_and_lowercases() {
        let normalized = normalize_sha256("SHA256:ABCDEF1234");
        assert_eq!(normalized, "abcdef1234");
    }

    #[test]
    fn verify_bytes_sha256_accepts_valid_hash() {
        let payload = br#"{"version":"1.2.3"}"#;
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let expected = format!("SHA256:{:x}", hasher.finalize()).to_uppercase();

        assert!(verify_bytes_sha256(payload, &expected).is_ok());
    }

    #[test]
    fn verify_bytes_sha256_rejects_hash_mismatch() {
        let payload = br#"{"version":"1.2.3"}"#;
        let result = verify_bytes_sha256(payload, "sha256:deadbeef");
        assert!(result.is_err());
    }

    #[test]
    fn verify_manifest_payload_accepts_matching_fields() {
        let selected = make_selected_release("v1.2.3-beta.1", "1.2.3-beta.1", true);
        let url = latest_json_url_for_tag("v1.2.3-beta.1");
        let manifest = make_manifest(
            "1.2.3-beta.1",
            "v1.2.3-beta.1",
            "live",
            &url,
            "sha256:deadbeef",
        );

        assert!(verify_manifest_payload(&manifest, &selected, &url).is_ok());
    }

    #[test]
    fn verify_manifest_payload_rejects_mismatched_fields() {
        let selected = make_selected_release("v1.2.3", "1.2.3", false);
        let expected_url = latest_json_url_for_tag("v1.2.3");
        let wrong = make_manifest("1.2.4", "v1.2.4", "live", "https://wrong/latest.json", "x");

        assert!(verify_manifest_payload(&wrong, &selected, &expected_url).is_err());
    }

    #[test]
    fn verify_manifest_signature_accepts_valid_signature() {
        let manifest_bytes = br#"{"version":"1.2.3"}"#;
        let (public_key, signature_b64) = sign_payload(manifest_bytes);

        assert!(
            verify_manifest_signature_with_public_key(manifest_bytes, &signature_b64, &public_key)
                .is_ok()
        );
    }

    #[test]
    fn verify_manifest_signature_rejects_tampered_manifest() {
        let manifest_bytes = br#"{"version":"1.2.3"}"#;
        let tampered_bytes = br#"{"version":"9.9.9"}"#;
        let (public_key, signature_b64) = sign_payload(manifest_bytes);

        assert!(
            verify_manifest_signature_with_public_key(tampered_bytes, &signature_b64, &public_key)
                .is_err()
        );
    }

    #[test]
    fn verify_manifest_signature_rejects_tampered_signature() {
        let manifest_bytes = br#"{"version":"1.2.3"}"#;
        let (public_key, signature_b64) = sign_payload(manifest_bytes);

        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(signature_b64)
            .unwrap();
        bytes[0] ^= 0xAA;
        let tampered_signature = base64::engine::general_purpose::STANDARD.encode(bytes);

        assert!(
            verify_manifest_signature_with_public_key(
                manifest_bytes,
                &tampered_signature,
                &public_key
            )
            .is_err()
        );
    }
}
