//! Keeping SwiftTunnel Lite up to date.
//!
//! Lite had no updater at all. That is tolerable for an app nobody can be
//! forced off, and it stops being tolerable the moment a version floor exists:
//! a client that cannot update and is refused by the server is simply dead, and
//! its owner has no way to know that downloading it again is the fix.
//!
//! # What is trusted
//!
//! Nothing that is not signed. The release publishes a small manifest signed
//! with our Ed25519 key, and that manifest carries each Lite installer's URL
//! and SHA-256. So:
//!
//! 1. Fetch the manifest and its detached signature.
//! 2. Verify the signature against the key compiled into this build.
//! 3. Read the installer entry for this architecture out of the *verified*
//!    manifest.
//! 4. Download it and check its SHA-256 against the one the manifest gave.
//! 5. Only then hand the file to `msiexec`.
//!
//! Anything that fails leaves the installed version alone. An update that
//! cannot be verified is not an update, and refusing it is always safer than
//! running it: the cost of skipping one is an out of date client, and the cost
//! of running the wrong one is arbitrary code as administrator.
//!
//! Unlike the desktop updater this does not go through the GitHub releases API
//! at all. `releases/latest/download/...` redirects to whatever the newest
//! release is, which needs no token, no rate limit budget, and no release
//! listing to parse.

use semver::Version;
use serde::Deserialize;

use crate::update_verify::{verify_bytes_sha256, verify_manifest_signature_with_public_key};

const MANIFEST_URL: &str = "https://github.com/Swift-tunnel/swifttunnel-app/releases/latest/download/swifttunnel-update-manifest.json";
const SIGNATURE_URL: &str = "https://github.com/Swift-tunnel/swifttunnel-app/releases/latest/download/swifttunnel-update-manifest.sig";

/// Replaced at build time. A build that still carries this cannot verify
/// anything and refuses to update rather than trusting a download.
const PUBLIC_KEY_PLACEHOLDER: &str = "REPLACE_WITH_UPDATE_MANIFEST_PUBLIC_KEY_B64";

/// Nothing we publish is anywhere near this. It exists so a redirect to
/// something enormous cannot be streamed into memory.
const MAX_INSTALLER_BYTES: u64 = 128 * 1024 * 1024;

const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Debug, Deserialize)]
struct SignedManifest {
    version: String,
    tag: String,
    #[serde(default)]
    lite: Option<LiteAssets>,
}

#[derive(Debug, Deserialize)]
struct LiteAssets {
    #[serde(default)]
    x64: Option<LiteAsset>,
    #[serde(default)]
    arm64: Option<LiteAsset>,
}

#[derive(Debug, Clone, Deserialize)]
struct LiteAsset {
    file: String,
    url: String,
    sha256: String,
    #[serde(default)]
    size: u64,
}

/// A newer Lite that the signed manifest vouches for.
#[derive(Debug, Clone)]
pub struct AvailableUpdate {
    pub version: Version,
    pub tag: String,
    pub file: String,
    url: String,
    sha256: String,
    size: u64,
}

impl AvailableUpdate {
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// The key this build verifies manifests with.
///
/// A runtime variable wins so a release can be tested against a different key
/// without a rebuild. Absent both, the placeholder is left, and that is treated
/// as "cannot verify" rather than "no verification needed".
fn manifest_public_key_b64() -> Result<String, String> {
    let key = std::env::var("SWIFTTUNNEL_UPDATE_MANIFEST_PUBLIC_KEY_B64")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            option_env!("SWIFTTUNNEL_UPDATE_MANIFEST_PUBLIC_KEY_B64")
                .unwrap_or(PUBLIC_KEY_PLACEHOLDER)
                .trim()
                .to_string()
        });

    if key.is_empty() || key == PUBLIC_KEY_PLACEHOLDER {
        return Err("this build has no update manifest key, so updates cannot be verified".into());
    }
    Ok(key)
}

/// Which installer this build should replace itself with.
///
/// Its own architecture, deliberately, not the machine's. An x64 build running
/// under emulation on an ARM64 machine is still an x64 product, and swapping it
/// for the ARM64 one mid-update changes which product is installed.
fn asset_for_this_build(assets: &LiteAssets) -> Option<&LiteAsset> {
    if cfg!(target_arch = "aarch64") {
        assets.arm64.as_ref()
    } else {
        assets.x64.as_ref()
    }
}

fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .user_agent(concat!("SwiftTunnel-Lite/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("could not build an HTTP client: {e}"))
}

/// Is there a newer Lite than `current_version`?
///
/// `Ok(None)` means up to date. An error means we could not find out, which is
/// not the same thing and must not be reported as being current.
pub async fn check_for_update(current_version: &str) -> Result<Option<AvailableUpdate>, String> {
    let current = Version::parse(current_version.trim_start_matches('v'))
        .map_err(|e| format!("this build has an unreadable version '{current_version}': {e}"))?;

    let public_key = base64_decode(&manifest_public_key_b64()?)?;
    let client = http_client()?;

    let manifest_bytes = fetch(&client, MANIFEST_URL, "update manifest").await?;
    let signature = String::from_utf8(fetch(&client, SIGNATURE_URL, "manifest signature").await?)
        .map_err(|_| "the manifest signature was not text".to_string())?;

    // Against the bytes as fetched. Parsing and re-encoding would change the
    // whitespace the signature was made over.
    verify_manifest_signature_with_public_key(&manifest_bytes, &signature, &public_key)?;

    let manifest: SignedManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("the update manifest could not be read: {e}"))?;

    let latest = Version::parse(manifest.version.trim_start_matches('v')).map_err(|e| {
        format!(
            "the manifest version '{}' is unreadable: {e}",
            manifest.version
        )
    })?;

    if latest <= current {
        return Ok(None);
    }

    let assets = manifest
        .lite
        .as_ref()
        .ok_or("the latest release publishes no Lite installer")?;
    let asset = asset_for_this_build(assets)
        .ok_or("the latest release has no Lite installer for this architecture")?;

    Ok(Some(AvailableUpdate {
        version: latest,
        tag: manifest.tag,
        file: asset.file.clone(),
        url: asset.url.clone(),
        sha256: asset.sha256.clone(),
        size: asset.size,
    }))
}

/// Download the installer, check it against the manifest, and save it.
///
/// Returns the path it was written to. Saved under `%ProgramData%` rather than
/// a temporary directory: Windows records the folder an install ran from as the
/// product's source and needs it again to remove that version later, and a
/// temporary one is gone by then.
pub async fn download_verified(update: &AvailableUpdate) -> Result<std::path::PathBuf, String> {
    let client = http_client()?;
    let bytes = fetch(&client, &update.url, &update.file).await?;

    // The manifest is signed, so its size is trustworthy and a mismatch means
    // this is not the file it described.
    if update.size > 0 && bytes.len() as u64 != update.size {
        return Err(format!(
            "{} is {} bytes, the signed manifest says {}",
            update.file,
            bytes.len(),
            update.size
        ));
    }

    verify_bytes_sha256(&bytes, &update.sha256, &update.file)?;

    let dir = installers_dir()?;
    let path = dir.join(&update.file);
    std::fs::write(&path, &bytes).map_err(|e| format!("could not save {}: {e}", path.display()))?;

    log::info!(
        "verified {} ({} bytes) and staged it at {}",
        update.file,
        bytes.len(),
        path.display()
    );
    Ok(path)
}

/// Hand a verified installer to msiexec.
///
/// Only ever called with a path returned by [`download_verified`], which is
/// what makes this safe: by here the bytes have been checked against a signed
/// manifest.
pub fn launch_installer(path: &std::path::Path) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!("{} is not there any more", path.display()));
    }
    std::process::Command::new("msiexec")
        .arg("/i")
        .arg(path)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("could not start the installer: {e}"))
}

fn installers_dir() -> Result<std::path::PathBuf, String> {
    let base = std::env::var_os("ProgramData").ok_or("ProgramData is not set")?;
    let dir = std::path::PathBuf::from(base)
        .join("SwiftTunnel")
        .join("installers");
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    Ok(dir)
}

fn base64_decode(value: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|e| format!("the update manifest key is not valid base64: {e}"))
}

async fn fetch(client: &reqwest::Client, url: &str, what: &str) -> Result<Vec<u8>, String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("could not fetch the {what}: {e}"))?;

    if !response.status().is_success() {
        return Err(format!(
            "could not fetch the {what}: server said {}",
            response.status()
        ));
    }

    // Refuse before reading, so a redirect to something enormous cannot be
    // pulled into memory first and rejected afterwards.
    if let Some(len) = response.content_length()
        && len > MAX_INSTALLER_BYTES
    {
        return Err(format!(
            "the {what} is {len} bytes, past the {MAX_INSTALLER_BYTES} byte limit"
        ));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("could not read the {what}: {e}"))?;

    if bytes.len() as u64 > MAX_INSTALLER_BYTES {
        return Err(format!(
            "the {what} is {} bytes, past the {MAX_INSTALLER_BYTES} byte limit",
            bytes.len()
        ));
    }

    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assets(x64: Option<&str>, arm64: Option<&str>) -> LiteAssets {
        let make = |file: &str| LiteAsset {
            file: file.to_string(),
            url: format!("https://example.invalid/{file}"),
            sha256: "00".repeat(32),
            size: 10,
        };
        LiteAssets {
            x64: x64.map(make),
            arm64: arm64.map(make),
        }
    }

    /// A build must replace itself with its own architecture.
    ///
    /// An x64 build running under emulation on an ARM64 machine is still the
    /// x64 product. Handing it the ARM64 installer would change which product
    /// is installed partway through an update.
    #[test]
    fn a_build_updates_to_its_own_architecture() {
        let both = assets(Some("lite_x64.msi"), Some("lite_arm64.msi"));
        let chosen = asset_for_this_build(&both).expect("an entry for this build");
        if cfg!(target_arch = "aarch64") {
            assert_eq!(chosen.file, "lite_arm64.msi");
        } else {
            assert_eq!(chosen.file, "lite_x64.msi");
        }
    }

    /// Missing our architecture is refused, not silently swapped for the other.
    #[test]
    fn a_missing_architecture_is_not_substituted() {
        let only_other = if cfg!(target_arch = "aarch64") {
            assets(Some("lite_x64.msi"), None)
        } else {
            assets(None, Some("lite_arm64.msi"))
        };
        assert!(asset_for_this_build(&only_other).is_none());
    }

    /// A build with no key compiled in must refuse to update rather than
    /// install something it cannot check.
    #[test]
    fn a_build_without_a_key_refuses_to_verify() {
        // Only meaningful when the environment is not supplying one.
        if std::env::var("SWIFTTUNNEL_UPDATE_MANIFEST_PUBLIC_KEY_B64").is_ok() {
            return;
        }
        if option_env!("SWIFTTUNNEL_UPDATE_MANIFEST_PUBLIC_KEY_B64").is_some() {
            return;
        }
        let error = manifest_public_key_b64().expect_err("a keyless build cannot verify");
        assert!(
            error.contains("cannot be verified"),
            "the error should say verification is impossible, got: {error}"
        );
    }

    #[test]
    fn a_manifest_without_lite_is_reported_not_ignored() {
        let manifest: SignedManifest =
            serde_json::from_str(r#"{"version":"9.9.9","tag":"v9.9.9"}"#).unwrap();
        assert!(manifest.lite.is_none());
    }

    /// The fields the updater depends on must survive a real manifest shape,
    /// including keys it does not know about.
    #[test]
    fn a_manifest_with_lite_parses() {
        let manifest: SignedManifest = serde_json::from_str(
            r#"{
                "version":"3.1.3","tag":"v3.1.3","channel_class":"stable",
                "latest_json_url":"https://example.invalid/latest.json",
                "latest_json_sha256":"abc",
                "lite":{
                  "x64":{"file":"SwiftTunnelLite_3.1.3_x64_en-US.msi",
                         "url":"https://example.invalid/x64.msi",
                         "sha256":"aa","size":123},
                  "arm64":{"file":"SwiftTunnelLite_3.1.3_arm64_en-US.msi",
                           "url":"https://example.invalid/arm64.msi",
                           "sha256":"bb","size":456}
                }
            }"#,
        )
        .expect("a real manifest shape must parse");

        assert_eq!(manifest.version, "3.1.3");
        let lite = manifest.lite.expect("lite entries");
        assert_eq!(lite.x64.unwrap().size, 123);
        assert_eq!(lite.arm64.unwrap().sha256, "bb");
    }
}
