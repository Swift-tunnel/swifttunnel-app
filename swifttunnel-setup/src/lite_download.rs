//! Download a Lite MSI only after authenticating the published release manifest.
use crate::update_verify::{verify_bytes_sha256, verify_manifest_signature_with_public_key};
use base64::Engine;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::{io::Read, time::Duration};
use swifttunnel_installer_cache::{InstallerCache, ProtectedInstaller};

const RELEASES: &str = "https://github.com/Swift-tunnel/swifttunnel-app/releases/";
const MAX_MSI: usize = 128 * 1024 * 1024;

#[derive(Deserialize)]
struct Manifest {
    version: String,
    tag: String,
    lite: Assets,
}
#[derive(Deserialize)]
struct Assets {
    x64: Option<Asset>,
    arm64: Option<Asset>,
}
#[derive(Deserialize)]
struct Asset {
    file: String,
    url: String,
    sha256: String,
    size: u64,
}

fn verify_asset(
    bytes: &[u8],
    signature: &str,
    key: &[u8],
    arch: &str,
) -> Result<(String, Asset), String> {
    verify_manifest_signature_with_public_key(bytes, signature, key)?;
    let manifest: Manifest =
        serde_json::from_slice(bytes).map_err(|_| "The Lite release information is invalid.")?;
    let version =
        semver::Version::parse(&manifest.version).map_err(|_| "The Lite version is invalid.")?;
    if !version.pre.is_empty() || !version.build.is_empty() || manifest.tag != format!("v{version}")
    {
        return Err("The latest Lite release is not a stable version.".into());
    }
    let asset = match arch {
        "x64" => manifest.lite.x64,
        "arm64" => manifest.lite.arm64,
        _ => return Err("This PC architecture is unsupported.".into()),
    }
    .ok_or("Lite is not published for this PC yet. Try again later.")?;
    let expected = format!("SwiftTunnelLite_{version}_{arch}_en-US.msi");
    if asset.file != expected
        || asset.url != format!("{RELEASES}download/{}/{expected}", manifest.tag)
        || asset.size < 1_000_000
        || asset.size > MAX_MSI as u64
        || asset.sha256.len() != 64
        || !asset.sha256.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return Err("The Lite package information is invalid. Nothing was installed.".into());
    }
    Ok((version.to_string(), asset))
}

fn fetch(
    client: &Client,
    url: &str,
    limit: usize,
    timeout: Duration,
    mut progress: impl FnMut(usize),
) -> Result<Vec<u8>, String> {
    let mut response =
        client.get(url).timeout(timeout).send().map_err(|_| {
            "Could not download Lite. Check your internet connection and try again."
        })?;
    if !response.status().is_success() {
        return Err(format!(
            "Lite download is unavailable (HTTP {}). Try again later.",
            response.status().as_u16()
        ));
    }
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err("Lite download exceeded its expected size.".into());
    }
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = response
            .read(&mut buffer)
            .map_err(|_| "Lite download was interrupted. Check your connection and retry.")?;
        if n == 0 {
            break;
        }
        if bytes.len().saturating_add(n) > limit {
            return Err("Lite download exceeded its expected size.".into());
        }
        bytes.extend_from_slice(&buffer[..n]);
        progress(bytes.len());
    }
    Ok(bytes)
}

fn native_architecture() -> Result<&'static str, String> {
    use windows::Win32::System::SystemInformation::*;
    use windows::Win32::System::Threading::{GetCurrentProcess, IsWow64Process2};
    unsafe {
        let mut process = IMAGE_FILE_MACHINE_UNKNOWN;
        let mut native = IMAGE_FILE_MACHINE_UNKNOWN;
        IsWow64Process2(GetCurrentProcess(), &mut process, Some(&mut native))
            .map_err(|_| "Could not identify this PC's architecture. Nothing was downloaded.")?;
        match native {
            IMAGE_FILE_MACHINE_AMD64 => Ok("x64"),
            IMAGE_FILE_MACHINE_ARM64 => Ok("arm64"),
            _ => Err("SwiftTunnel Lite requires 64-bit Windows (x64 or ARM64).".into()),
        }
    }
}

pub(crate) fn fetch_verified(
    mut progress: impl FnMut(String),
) -> Result<(Vec<u8>, String, String), String> {
    let key = option_env!("SWIFTTUNNEL_UPDATE_MANIFEST_PUBLIC_KEY_B64").unwrap_or("");
    let key = base64::engine::general_purpose::STANDARD.decode(key.trim())
        .ok().filter(|k| k.len() == 32).ok_or("This Setup cannot verify Lite downloads. Download a current Setup from swifttunnel.net.")?;
    let arch = native_architecture()?;
    let client = Client::builder()
        .https_only(true)
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent("SwiftTunnel-Setup")
        .build()
        .map_err(|_| "Could not initialize secure downloads.")?;
    progress("Checking the Lite release".into());
    let manifest = fetch(
        &client,
        &format!("{RELEASES}latest/download/swifttunnel-update-manifest.json"),
        1024 * 1024,
        Duration::from_secs(20),
        |_| {},
    )?;
    let signature = fetch(
        &client,
        &format!("{RELEASES}latest/download/swifttunnel-update-manifest.sig"),
        4096,
        Duration::from_secs(20),
        |_| {},
    )?;
    let signature =
        std::str::from_utf8(&signature).map_err(|_| "The Lite release signature is invalid.")?;
    let (version, asset) = verify_asset(&manifest, signature, &key, arch)?;
    let mut percent = usize::MAX;
    let bytes = fetch(
        &client,
        &asset.url,
        asset.size as usize,
        Duration::from_secs(180),
        |received| {
            let next = (received as u64 * 100 / asset.size) as usize;
            if next != percent {
                percent = next;
                progress(format!("Downloading Lite: {next}%"));
            }
        },
    )?;
    if bytes.len() as u64 != asset.size {
        return Err("The Lite download is incomplete. Try again.".into());
    }
    progress("Verifying Lite".into());
    verify_bytes_sha256(&bytes, &asset.sha256, "Lite installer")?;
    Ok((bytes, version, asset.file))
}

pub fn download(progress: impl FnMut(String)) -> Result<(ProtectedInstaller, String), String> {
    let (bytes, version, file) = fetch_verified(progress)?;
    let source = InstallerCache::open()
        .and_then(|c| c.stage(&file, &bytes))
        .map_err(|_| "Could not save Lite's installer. Check available disk space and retry.")?;
    Ok((source, version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    #[test]
    fn download_rejects_oversized_truncated_and_failed_http_responses() {
        use std::{io::Write, net::TcpListener};
        for response in [
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n12345",
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n12",
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n12345",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut connection, _) = listener.accept().unwrap();
                connection
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = [0u8; 2048];
                let _ = connection.read(&mut request);
                let _ = connection.write_all(response.as_bytes());
            });
            let client = Client::builder().no_proxy().build().unwrap();
            assert!(fetch(
                &client,
                &format!("http://{address}/"),
                4,
                Duration::from_secs(2),
                |_| {}
            )
            .is_err());
            server.join().unwrap();
        }
    }
    fn signed(arch: &str) -> (Vec<u8>, String, Vec<u8>) {
        let key = Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap();
        let file = format!("SwiftTunnelLite_3.1.6_{arch}_en-US.msi");
        let bytes = serde_json::to_vec(&serde_json::json!({"version":"3.1.6","tag":"v3.1.6","lite":{arch:{"file":file,"url":format!("{RELEASES}download/v3.1.6/{file}"),"sha256":"ab".repeat(32),"size":2000000}}})).unwrap();
        let signature = base64::engine::general_purpose::STANDARD.encode(key.sign(&bytes).as_ref());
        (bytes, signature, key.public_key().as_ref().to_vec())
    }
    #[test]
    fn requires_verified_matching_lite_architecture() {
        for arch in ["x64", "arm64"] {
            let (mut bytes, sig, key) = signed(arch);
            assert!(verify_asset(&bytes, &sig, &key, arch).is_ok());
            assert!(verify_asset(
                &bytes,
                &sig,
                &key,
                if arch == "x64" { "arm64" } else { "x64" }
            )
            .is_err());
            bytes.push(b' ');
            assert!(verify_asset(&bytes, &sig, &key, arch).is_err());
        }
    }
    #[test]
    fn rejects_wrong_product_url_and_oversized_metadata_even_if_signed() {
        let (bytes, _, _) = signed("x64");
        let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for (field, value) in [
            ("file", serde_json::json!("SwiftTunnel_3.1.6_x64_en-US.msi")),
            ("url", serde_json::json!("https://example.com/other.msi")),
            ("size", serde_json::json!(MAX_MSI + 1)),
            ("sha256", serde_json::json!("invalid")),
        ] {
            let mut changed = original.clone();
            changed["lite"]["x64"][field] = value;
            let bytes = serde_json::to_vec(&changed).unwrap();
            let key = Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap();
            let sig = base64::engine::general_purpose::STANDARD.encode(key.sign(&bytes).as_ref());
            assert!(verify_asset(&bytes, &sig, key.public_key().as_ref(), "x64").is_err());
        }
    }
}
