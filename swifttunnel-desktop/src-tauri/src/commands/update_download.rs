//! Download only the package named by the already verified release metadata.
use base64::Engine as _;
use minisign_verify::{PublicKey, Signature};
use semver::Version;
use std::time::{Duration, Instant};
use tauri_plugin_updater::RemoteRelease;
use url::Url;

const MAX_INSTALLER_BYTES: usize = 256 * 1024 * 1024;
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug)]
pub(super) struct Package {
    url: Url,
    signature: String,
}

impl Package {
    pub(super) fn from_metadata(
        bytes: &[u8],
        expected_version: &Version,
        tag: &str,
        arch: &str,
    ) -> Result<Self, String> {
        let release: RemoteRelease = serde_json::from_slice(bytes)
            .map_err(|error| format!("Could not read update metadata: {error}"))?;
        if &release.version != expected_version {
            return Err("The update metadata does not match this release. Please retry.".into());
        }
        // Match the running app, including x64 apps on ARM Windows. Prefer the
        // explicit MSI target, as the existing installer handoff uses msiexec.
        let targets = [format!("windows-{arch}-msi"), format!("windows-{arch}")];
        let (url, signature) = targets
            .iter()
            .find_map(|target| {
                Some((
                    release.download_url(target).ok()?,
                    release.signature(target).ok()?,
                ))
            })
            .ok_or_else(|| {
                "No update installer is available for this app's architecture.".to_string()
            })?;
        let prefix = format!("/Swift-tunnel/swifttunnel-app/releases/download/{tag}/");
        if url.scheme() != "https"
            || url.host_str() != Some("github.com")
            || url.port().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.path().starts_with(&prefix)
            || !url.path().ends_with(".msi")
        {
            return Err("The update installer address does not match this release.".into());
        }
        // Reject malformed signatures before downloading a potentially large file.
        decode_signature(signature)?;
        Ok(Self {
            url: url.clone(),
            signature: signature.clone(),
        })
    }

    pub(super) async fn download(
        &self,
        progress: impl FnMut(u64, Option<u64>),
    ) -> Result<Vec<u8>, String> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(300))
            .redirect(reqwest::redirect::Policy::limited(5))
            .user_agent("SwiftTunnel-Updater")
            .build()
            .map_err(|error| format!("Could not prepare the update download: {error}"))?;
        let response =
            client.get(self.url.clone()).send().await.map_err(|error| {
                format!("Could not download the update. Please retry. ({error})")
            })?;
        read_package(response, MAX_INSTALLER_BYTES, progress).await
    }

    pub(super) fn verify(
        &self,
        bytes: &[u8],
        primary_key: &str,
        legacy_key: Option<&str>,
    ) -> Result<(), String> {
        verify_package(bytes, &self.signature, primary_key, legacy_key)
    }
}

async fn read_package(
    mut response: reqwest::Response,
    limit: usize,
    mut progress: impl FnMut(u64, Option<u64>),
) -> Result<Vec<u8>, String> {
    if !response.status().is_success() {
        return Err(format!(
            "The update download failed (HTTP {}). Please retry.",
            response.status()
        ));
    }
    let total = response.content_length();
    let oversized = || {
        "The update download is too large. Use the installer from the official release or contact support@swifttunnel.net.".to_string()
    };
    if total.is_some_and(|length| length > limit as u64) {
        return Err(oversized());
    }
    let mut bytes = Vec::new();
    let mut last_progress = Instant::now();
    progress(0, total);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("The update download was interrupted. Please retry. ({error})"))?
    {
        if chunk.len() > limit.saturating_sub(bytes.len()) {
            return Err(oversized());
        }
        bytes.try_reserve(chunk.len()).map_err(|_| {
            "Not enough memory to download the update. Close other apps and retry.".to_string()
        })?;
        bytes.extend_from_slice(&chunk);
        if last_progress.elapsed() >= PROGRESS_INTERVAL {
            progress(bytes.len() as u64, total);
            last_progress = Instant::now();
        }
    }
    if bytes.is_empty() || total.is_some_and(|length| length != bytes.len() as u64) {
        return Err("The update download is incomplete. Please retry.".into());
    }
    progress(bytes.len() as u64, total);
    Ok(bytes)
}

fn decode_text(encoded: &str) -> Result<String, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|_| {
            "The update signing information is invalid. Please contact support@swifttunnel.net."
                .to_string()
        })?;
    String::from_utf8(bytes)
        .map_err(|_| "The update signing information is not valid text.".to_string())
}

fn decode_signature(encoded: &str) -> Result<Signature, String> {
    Signature::decode(&decode_text(encoded)?).map_err(|_| {
        "The update signature is invalid. Please retry or contact support@swifttunnel.net."
            .to_string()
    })
}

fn verify_package(
    bytes: &[u8],
    signature: &str,
    primary: &str,
    legacy: Option<&str>,
) -> Result<(), String> {
    let signature = decode_signature(signature)?;
    let primary = PublicKey::decode(&decode_text(primary)?).map_err(|_| {
        "This app's update key is invalid. Download the installer from the official release."
            .to_string()
    })?;
    // Use the same library and allow_legacy setting as tauri-plugin-updater.
    // Only a genuine signature/key mismatch permits the existing key rotation fallback.
    match primary.verify(bytes, &signature, true) {
        Ok(()) => return Ok(()),
        Err(minisign_verify::Error::UnexpectedKeyId | minisign_verify::Error::InvalidSignature) => {
        }
        Err(_) => return Err("The update signature could not be verified. Please retry.".into()),
    }
    if let Some(legacy) = legacy {
        let legacy = PublicKey::decode(&decode_text(legacy)?).map_err(|_| {
            "The previous update key is invalid. Please contact support@swifttunnel.net."
                .to_string()
        })?;
        if legacy.verify(bytes, &signature, true).is_ok() {
            return Ok(());
        }
    }
    Err("The update signature did not match. The installer was not started. Please retry or contact support@swifttunnel.net.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use std::io::{Read, Write};

    // Build a real legacy Minisign message with fresh, test-only keys. Tauri
    // accepts this mode too; the prehashed fixture below covers its newer mode.
    fn signed(bytes: &[u8]) -> (String, String) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let mut key = b"Ed".to_vec();
        key.extend_from_slice(&pair.public_key().as_ref()[..8]);
        key.extend_from_slice(pair.public_key().as_ref());
        let sig = pair.sign(bytes);
        let mut packet = b"Ed".to_vec();
        packet.extend_from_slice(&pair.public_key().as_ref()[..8]);
        packet.extend_from_slice(sig.as_ref());
        let comment = "test-only";
        let global = pair.sign(&[sig.as_ref(), comment.as_bytes()].concat());
        let b64 = base64::engine::general_purpose::STANDARD;
        (
            b64.encode(format!("untrusted comment: test key\n{}", b64.encode(key))),
            b64.encode(format!(
                "untrusted comment: test signature\n{}\ntrusted comment: {comment}\n{}\n",
                b64.encode(packet),
                b64.encode(global.as_ref())
            )),
        )
    }

    #[test]
    fn signatures_reject_tampering_and_rotate_only_to_a_trusted_key() {
        let (current, signature) = signed(b"installer");
        let (other, _) = signed(b"installer");
        assert!(verify_package(b"installer", &signature, &current, None).is_ok());
        assert!(verify_package(b"changed", &signature, &current, Some(&other)).is_err());
        assert!(verify_package(b"installer", &signature, &other, None).is_err());
        assert!(verify_package(b"installer", &signature, &other, Some(&current)).is_ok());
        assert!(verify_package(b"installer", &signature, "invalid", Some(&current)).is_err());
        assert!(verify_package(b"installer", "invalid", &current, Some(&other)).is_err());
        let changed_comment = base64::engine::general_purpose::STANDARD.encode(
            decode_text(&signature)
                .unwrap()
                .replace("trusted comment: test-only", "trusted comment: changed"),
        );
        assert!(verify_package(b"installer", &changed_comment, &current, None).is_err());
    }

    #[test]
    fn prehashed_minisign_fixture_remains_compatible() {
        // Public test vector from minisign-verify 0.2.5, also used by Tauri.
        let b64 = base64::engine::general_purpose::STANDARD;
        let key = b64.encode("untrusted comment: minisign public key E7620F1842B4E81F\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3");
        let signature = b64.encode("untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1556193335\tfile:test\ny/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==");
        assert!(verify_package(b"test", &signature, &key, None).is_ok());
        assert!(verify_package(b"Test", &signature, &key, None).is_err());
    }

    fn metadata(platforms: serde_json::Value, version: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"version": version, "platforms": platforms}))
            .unwrap()
    }

    fn entry(url: &str) -> serde_json::Value {
        let (_, signature) = signed(b"installer");
        serde_json::json!({"url": url, "signature": signature})
    }

    #[test]
    fn metadata_picks_the_running_architecture_and_prefers_msi() {
        let root = "https://github.com/Swift-tunnel/swifttunnel-app/releases/download/v9.0.0";
        let bytes = metadata(
            serde_json::json!({
                "windows-x86_64": entry(&format!("{root}/generic.msi")),
                "windows-x86_64-msi": entry(&format!("{root}/x64.msi")),
                "windows-aarch64-msi": entry(&format!("{root}/arm64.msi"))
            }),
            "9.0.0",
        );
        let version = Version::parse("9.0.0").unwrap();
        assert!(
            Package::from_metadata(&bytes, &version, "v9.0.0", "x86_64")
                .unwrap()
                .url
                .path()
                .ends_with("/x64.msi")
        );
        assert!(
            Package::from_metadata(&bytes, &version, "v9.0.0", "aarch64")
                .unwrap()
                .url
                .path()
                .ends_with("/arm64.msi")
        );
        assert!(Package::from_metadata(&bytes, &version, "v9.0.0", "x86").is_err());
        assert!(
            Package::from_metadata(
                &bytes,
                &Version::parse("8.0.0").unwrap(),
                "v9.0.0",
                "x86_64"
            )
            .is_err()
        );
    }

    #[test]
    fn metadata_accepts_generic_msi_but_rejects_wrong_release_origin_or_format() {
        let version = Version::parse("9.0.0").unwrap();
        for (url, valid) in [
            (
                "https://github.com/Swift-tunnel/swifttunnel-app/releases/download/v9.0.0/setup.msi",
                true,
            ),
            (
                "http://github.com/Swift-tunnel/swifttunnel-app/releases/download/v9.0.0/setup.msi",
                false,
            ),
            (
                "https://github.com/other/app/releases/download/v9.0.0/setup.msi",
                false,
            ),
            (
                "https://github.com/Swift-tunnel/swifttunnel-app/releases/download/v8.0.0/setup.msi",
                false,
            ),
            (
                "https://github.com/Swift-tunnel/swifttunnel-app/releases/download/v9.0.0/setup.exe",
                false,
            ),
            (
                "https://github.com/Swift-tunnel/swifttunnel-app/releases/download/v9.0.0/setup.msi?override=1",
                false,
            ),
        ] {
            let bytes = metadata(serde_json::json!({"windows-x86_64": entry(url)}), "9.0.0");
            assert_eq!(
                Package::from_metadata(&bytes, &version, "v9.0.0", "x86_64").is_ok(),
                valid,
                "{url}"
            );
        }
    }

    async fn download_wire(
        wire: &'static [u8],
        limit: usize,
    ) -> (Result<Vec<u8>, String>, Vec<u64>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (done, finish) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let _ = socket.read(&mut [0; 4096]);
            let _ = socket.write_all(wire);
            // A missing EOF is deliberate. Oversize and idle-timeout checks
            // must stop waiting without relying on a cooperative server.
            let _ = finish.recv_timeout(Duration::from_secs(3));
        });
        let response = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .read_timeout(Duration::from_millis(150))
            .build()
            .unwrap()
            .get(format!("http://{address}"))
            .send()
            .await
            .unwrap();
        let mut progress = Vec::new();
        let result = read_package(response, limit, |read, _| progress.push(read)).await;
        let _ = done.send(());
        worker.join().unwrap();
        (result, progress)
    }

    #[tokio::test]
    async fn rejects_oversized_headers_without_reading_the_body() {
        let (result, progress) =
            download_wire(b"HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n", 8).await;
        assert!(result.unwrap_err().contains("too large"));
        assert!(progress.is_empty());
    }

    #[tokio::test]
    async fn rejects_chunked_overflow_before_end_of_download() {
        let (result, progress) = download_wire(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n12345678\r\n8\r\nabcdefgh\r\n", 12).await;
        assert!(result.unwrap_err().contains("too large"));
        assert!(!progress.contains(&16));
    }

    #[tokio::test]
    async fn complete_download_has_final_progress_and_no_per_chunk_event_flood() {
        let (result, progress) = download_wire(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n1\r\n1\r\n2\r\n1\r\n3\r\n1\r\n4\r\n1\r\n5\r\n1\r\n6\r\n1\r\n7\r\n1\r\n8\r\n0\r\n\r\n", 8).await;
        assert_eq!(result.unwrap(), b"12345678");
        assert_eq!(progress.first(), Some(&0));
        assert_eq!(progress.last(), Some(&8));
        assert!(progress.len() <= 3);
    }

    #[tokio::test]
    async fn unfinished_and_failed_downloads_do_not_report_completion() {
        for wire in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc"[..],
            &b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..],
        ] {
            let (result, progress) = download_wire(wire, 12).await;
            assert!(result.is_err());
            assert!(progress.iter().all(|bytes| *bytes == 0));
        }
    }
}
