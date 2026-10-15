//! Tools fetched on first use instead of being shipped inside the installer.
//!
//! # Why
//!
//! GoodbyeDPI and WinDivert are unsigned, and Microsoft Defender carries
//! deliberate `HackTool` signatures for both. They are dual-use network
//! manipulation tools, so that classification is not a mistake we can argue
//! our way out of. Bundling them meant every SwiftTunnel download carried two
//! files Defender is built to quarantine, and users reported the installer
//! being deleted out of their Downloads folder before it ever ran. Nearly all
//! of them had never touched the one feature those files exist for.
//!
//! Moving them out of the installer changes who is affected rather than
//! pretending the detection is wrong:
//!
//! - Everybody gets an installer that survives the download.
//! - Only people who turn on Country Ban bypass fetch the flagged files.
//! - If Defender takes them at that point too, [`ComponentError::Quarantined`]
//!   says so precisely, and the caller falls back to the relay, which is a path
//!   that already works and needs none of this.
//!
//! Nothing here alters the binaries or hides what they are. Every file is
//! verified against a hash pinned at build time, so a fetched component is
//! byte-for-byte the one we tested, and a tampered mirror cannot substitute
//! anything.

use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

/// Where components are served from.
///
/// Our own domain rather than the GitHub release assets: the releases are what
/// users download by hand, and attaching known-flagged binaries to them invites
/// the exact problem this module exists to solve.
const COMPONENT_BASE_URL: &str = "https://www.swifttunnel.net/components";

/// Override for local testing. Never set in production.
const COMPONENT_BASE_URL_ENV: &str = "SWIFTTUNNEL_COMPONENT_BASE_URL";

/// A component file, pinned to the exact bytes we tested against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentFile {
    /// Path under the component root, always forward slashes.
    pub relative_path: &'static str,
    /// Lowercase hex SHA-256 of the file.
    pub sha256: &'static str,
    pub size_bytes: u64,
}

/// A set of files fetched and installed together.
#[derive(Debug, Clone, Copy)]
pub struct OptionalComponent {
    pub id: &'static str,
    /// Bumped whenever any pinned file changes. Part of the install path, so an
    /// older version is never mistaken for a newer one and a downgrade cannot
    /// silently reuse the wrong bytes.
    pub version: &'static str,
    pub files: &'static [ComponentFile],
}

#[derive(Debug, thiserror::Error)]
pub enum ComponentError {
    #[error("could not reach {url}: {reason}")]
    Download { url: String, reason: String },

    #[error("{url} returned HTTP {status}")]
    HttpStatus { url: String, status: u16 },

    /// The bytes are not what we pinned. Never install them.
    #[error("{file} did not match its pinned hash (expected {expected}, got {actual})")]
    HashMismatch {
        file: String,
        expected: String,
        actual: String,
    },

    #[error("{file} did not match its pinned size of {expected} bytes")]
    SizeMismatch { file: String, expected: u64 },

    /// Files verified, written, and then gone. On Windows that is antivirus,
    /// essentially always, and saying so beats a generic IO error the user
    /// cannot act on.
    #[error(
        "{file} was removed right after it was written, which is almost always antivirus quarantine"
    )]
    Quarantined { file: String },

    #[error("{context}: {source}")]
    Io {
        context: String,
        source: std::io::Error,
    },
}

impl ComponentError {
    /// Whether the user can do anything about this by retrying.
    ///
    /// Quarantine and hash mismatches are not transient: retrying re-downloads
    /// the same bytes and hits the same wall. Network failures are worth
    /// another go.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            ComponentError::Download { .. } | ComponentError::HttpStatus { .. }
        )
    }
}

// ---------------------------------------------------------------------------
// The GoodbyeDPI component
// ---------------------------------------------------------------------------

/// Which payload a machine needs. ARM64 has no GoodbyeDPI build at all, which
/// is why it is absent here rather than empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentArch {
    X86,
    X64,
}

/// Bump alongside any change to the pinned files below.
const GOODBYEDPI_VERSION: &str = "2026-08-26";

const GOODBYEDPI_X64_FILES: &[ComponentFile] = &[
    ComponentFile {
        relative_path: "x86_64/goodbyedpi.exe",
        sha256: "331ac6c1d22ba5a0a217f3f27d0d823051869cafc8b8ef7f2002fa2accebc74e",
        size_bytes: 75264,
    },
    ComponentFile {
        relative_path: "x86_64/WinDivert.dll",
        sha256: "a97859785a2df1d4462e7d48d33ccbd89fedd40dac4970f4afd89e63f59ee1ec",
        size_bytes: 23552,
    },
    ComponentFile {
        relative_path: "x86_64/WinDivert64.sys",
        sha256: "53ab28ec00be6e6f8aefa9ee76fc2735e94d7f3f9dbc06eb2b7ac8cd3084a6af",
        size_bytes: 50592,
    },
];

const GOODBYEDPI_X86_FILES: &[ComponentFile] = &[
    ComponentFile {
        relative_path: "x86/goodbyedpi.exe",
        sha256: "234e7c679c3d36885bb9214fb86e4a555754c8416e2c6773e4832834f73ae686",
        size_bytes: 67584,
    },
    ComponentFile {
        relative_path: "x86/WinDivert.dll",
        sha256: "ab3cdd99d4c710821070568995ca4cb58fb4273e9c0516a16e3335218438efcc",
        size_bytes: 23040,
    },
    // The 32-bit build ships both drivers and picks by OS bitness at runtime,
    // so leaving either out breaks it on one of the two.
    ComponentFile {
        relative_path: "x86/WinDivert32.sys",
        sha256: "b2ef49a10d07df6db483e86516d2dfaaaa2f30f4a93dd152fa85f09f891cd049",
        size_bytes: 43936,
    },
    ComponentFile {
        relative_path: "x86/WinDivert64.sys",
        sha256: "53ab28ec00be6e6f8aefa9ee76fc2735e94d7f3f9dbc06eb2b7ac8cd3084a6af",
        size_bytes: 50592,
    },
];

pub fn goodbyedpi_component(arch: ComponentArch) -> OptionalComponent {
    OptionalComponent {
        id: "goodbyedpi",
        version: GOODBYEDPI_VERSION,
        files: match arch {
            ComponentArch::X64 => GOODBYEDPI_X64_FILES,
            ComponentArch::X86 => GOODBYEDPI_X86_FILES,
        },
    }
}

// ---------------------------------------------------------------------------
// Locations
// ---------------------------------------------------------------------------

/// Root for all installed components.
///
/// ProgramData, not LOCALAPPDATA. The app runs elevated, so `%LOCALAPPDATA%`
/// would resolve to whichever account UAC elevated into and could differ from
/// the person actually using the machine. A machine-wide location is the same
/// one every time.
pub fn components_root() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("SwiftTunnel").join("components")
}

/// Where a specific component version lives once installed.
pub fn component_dir(component: &OptionalComponent) -> PathBuf {
    components_root().join(component.id).join(component.version)
}

/// Where the GoodbyeDPI component lands once fetched.
///
/// Both arch manifests share this directory: they differ in which files
/// they pin, not in where those files go.
pub fn goodbyedpi_install_dir() -> PathBuf {
    component_dir(&goodbyedpi_component(ComponentArch::X64))
}

/// Download URL for one file of a component.
pub fn file_url(component: &OptionalComponent, file: &ComponentFile) -> String {
    let base = std::env::var(COMPONENT_BASE_URL_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| COMPONENT_BASE_URL.to_string());

    format!(
        "{}/{}/{}/{}",
        base.trim_end_matches('/'),
        component.id,
        component.version,
        file.relative_path
    )
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

pub fn sha256_of(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn verified_file(path: &Path, expected: &ComponentFile) -> Option<File> {
    // Refuse redirected paths and hold a read handle that denies modification
    // and deletion on Windows, including while the verified helper is running.
    crate::roblox_native_launch::safe_path(path).ok()?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1);
    }
    let mut file = options.open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() != expected.size_bytes {
        return None;
    }
    let mut hasher = Sha256::new();
    let mut remaining = expected.size_bytes;
    let mut buffer = [0; 16 * 1024];
    while remaining > 0 {
        let requested = remaining.min(buffer.len() as u64) as usize;
        let count = file.read(&mut buffer[..requested]).ok()?;
        if count == 0 {
            return None;
        }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    if file.read(&mut buffer[..1]).ok()? != 0
        || format!("{:x}", hasher.finalize()) != expected.sha256
    {
        return None;
    }
    Some(file)
}

/// Verify the executable and its sibling DLL/drivers, retaining their locks.
pub(crate) fn verified_flat_directory(
    component: &OptionalComponent,
    directory: &Path,
) -> Option<Vec<File>> {
    component
        .files
        .iter()
        .map(|file| {
            verified_file(
                &directory.join(Path::new(file.relative_path).file_name()?),
                file,
            )
        })
        .collect()
}

/// Whether an installed component is complete and unmodified.
///
/// Size is checked before hashing because it rejects the common failures (a
/// truncated write, a zero-byte stub left by a scanner) without reading the
/// whole file, and because a size mismatch already proves the hash cannot
/// match.
pub fn is_installed(component: &OptionalComponent) -> bool {
    let root = component_dir(component);
    component.files.iter().all(|file| {
        let path = root.join(file.relative_path);
        verified_file(&path, file).is_some()
    })
}

/// The installed executable for a component file, if the component is intact.
pub fn installed_path(component: &OptionalComponent, relative_path: &str) -> Option<PathBuf> {
    component
        .files
        .iter()
        .find(|file| file.relative_path == relative_path)?;
    is_installed(component).then(|| component_dir(component).join(relative_path))
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

/// Fetch and install a component, or confirm it is already there.
///
/// Every file is downloaded to a staging directory and hash-checked before
/// anything is moved into place, so a partial or tampered download never
/// becomes a half-installed component that later looks valid.
pub async fn ensure_installed(component: &OptionalComponent) -> Result<PathBuf, ComponentError> {
    // Both architectures share a version directory. Do not let concurrent
    // installs remove one another's staging files or live payload.
    static INSTALL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _install = INSTALL.lock().await;
    let root = component_dir(component);
    if is_installed(component) {
        return Ok(root);
    }

    let staging = Staging::create(&root)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| ComponentError::Download {
            url: COMPONENT_BASE_URL.to_string(),
            reason: e.to_string(),
        })?;

    for file in component.files {
        let url = file_url(component, file);
        let response =
            client
                .get(&url)
                .send()
                .await
                .map_err(|source| ComponentError::Download {
                    url: url.clone(),
                    reason: source.to_string(),
                })?;

        if !response.status().is_success() {
            return Err(ComponentError::HttpStatus {
                url,
                status: response.status().as_u16(),
            });
        }

        let bytes = read_component_body(response, file).await?;

        let actual = sha256_of(&bytes);
        if actual != file.sha256 {
            return Err(ComponentError::HashMismatch {
                file: file.relative_path.to_string(),
                expected: file.sha256.to_string(),
                actual,
            });
        }

        let dest = staging.path.join(file.relative_path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|source| ComponentError::Io {
                context: format!("could not create {}", parent.display()),
                source,
            })?;
        }
        std::fs::write(&dest, &bytes).map_err(|source| ComponentError::Io {
            context: format!("could not write {}", dest.display()),
            source,
        })?;
    }

    // Swap in only after every file has been verified.
    promote(&staging.path, &root)?;

    // Re-check after landing. A file that verified a moment ago and is now gone
    // was taken by something else on the machine, and on Windows that is
    // antivirus. Naming it lets the caller explain the failure instead of
    // reporting a mystery.
    for file in component.files {
        let path = root.join(file.relative_path);
        if !path.exists() {
            return Err(ComponentError::Quarantined {
                file: file.relative_path.to_string(),
            });
        }
    }

    Ok(root)
}

async fn read_component_body(
    mut response: reqwest::Response,
    file: &ComponentFile,
) -> Result<Vec<u8>, ComponentError> {
    let limit = usize::try_from(file.size_bytes).map_err(|_| ComponentError::SizeMismatch {
        file: file.relative_path.into(),
        expected: file.size_bytes,
    })?;
    let mismatch = || ComponentError::SizeMismatch {
        file: file.relative_path.into(),
        expected: file.size_bytes,
    };
    if response
        .content_length()
        .is_some_and(|size| size != file.size_bytes)
    {
        return Err(mismatch());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| ComponentError::Download {
            url: response.url().to_string(),
            reason: e.to_string(),
        })?
    {
        if chunk.len() > limit.saturating_sub(bytes.len()) {
            return Err(mismatch());
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() != limit {
        return Err(ComponentError::SizeMismatch {
            file: file.relative_path.into(),
            expected: file.size_bytes,
        });
    }
    Ok(bytes)
}

struct Staging {
    path: PathBuf,
}
impl Staging {
    fn create(root: &Path) -> Result<Self, ComponentError> {
        let parent = root.parent().ok_or_else(|| {
            component_io(
                "Invalid component location",
                std::io::Error::from(std::io::ErrorKind::InvalidInput),
            )
        })?;
        crate::roblox_native_launch::safe_path(parent).map_err(|e| {
            component_io("Component folder is redirected", std::io::Error::other(e))
        })?;
        std::fs::create_dir_all(parent)
            .map_err(|e| component_io("Could not create component folder", e))?;
        let path = parent.join(format!(
            ".{}.{}.staging",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path)
            .map_err(|e| component_io("Could not prepare component download", e))?;
        Ok(Self { path })
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        // Only the unique directory created by this attempt is ours to remove.
        if crate::roblox_native_launch::safe_path(&self.path).is_ok() {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
fn component_io(context: &str, source: std::io::Error) -> ComponentError {
    ComponentError::Io {
        context: context.into(),
        source,
    }
}
fn promote(staging: &Path, root: &Path) -> Result<(), ComponentError> {
    crate::roblox_native_launch::safe_path(root)
        .map_err(|e| component_io("Component folder is redirected", std::io::Error::other(e)))?;
    let backup = staging.with_extension("previous");
    let had_previous = match std::fs::rename(root, &backup) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(component_io("Could not preserve the existing component", e)),
    };
    if let Err(error) = std::fs::rename(staging, root) {
        if had_previous && let Err(restore) = std::fs::rename(&backup, root) {
            return Err(component_io(
                "Could not install the component; its previous files were kept beside it",
                std::io::Error::other(format!("{error}; restore: {restore}")),
            ));
        }
        return Err(component_io(
            "Could not install the component; the previous files were kept",
            error,
        ));
    }
    if had_previous {
        // This backup contains only the directory we just moved ourselves.
        if crate::roblox_native_launch::safe_path(&backup).is_ok() {
            let _ = std::fs::remove_dir_all(backup);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const TEST_FILE: ComponentFile = ComponentFile {
        relative_path: "test/helper.exe",
        sha256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        size_bytes: 5,
    };
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("swift-components-{:016x}", rand::random::<u64>()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn read_fixture(wire: &'static [u8]) -> Result<Vec<u8>, ComponentError> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (done, finish) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request);
            stream.write_all(wire).unwrap();
            let _ = finish.recv_timeout(std::time::Duration::from_secs(3));
        });
        let response = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap()
            .get(format!("http://{address}"))
            .send()
            .await
            .unwrap();
        let result = read_component_body(response, &TEST_FILE).await;
        let _ = done.send(());
        worker.join().unwrap();
        result
    }

    #[tokio::test]
    async fn component_downloads_refuse_oversized_fixed_or_chunked_bodies_before_eof() {
        for wire in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 1000000000\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nhello!\r\n".as_slice(),
        ] {
            let error = read_fixture(wire).await.unwrap_err();
            assert!(matches!(error, ComponentError::SizeMismatch { .. }));
            assert!(!error.is_transient());
        }
        assert_eq!(
            read_fixture(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
            )
            .await
            .unwrap(),
            b"hello"
        );
        assert!(matches!(
            read_fixture(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nhell").await,
            Err(ComponentError::SizeMismatch { .. })
        ));
    }

    #[test]
    fn installed_payload_checks_hash_and_keeps_verified_files_immutable() {
        let dir = Fixture::new();
        let file = dir.0.join("helper.exe");
        std::fs::write(&file, b"hello").unwrap();
        let component = OptionalComponent {
            id: "test",
            version: "1",
            files: &[TEST_FILE],
        };
        let verified = verified_flat_directory(&component, &dir.0).unwrap();
        #[cfg(windows)]
        {
            assert!(std::fs::write(&file, b"other").is_err());
            assert!(std::fs::remove_file(&file).is_err());
        }
        drop(verified);
        std::fs::write(&file, b"other").unwrap();
        assert!(verified_flat_directory(&component, &dir.0).is_none());
        std::fs::write(&file, b"hello!").unwrap();
        assert!(verified_flat_directory(&component, &dir.0).is_none());
    }

    #[test]
    fn an_executable_alone_cannot_bypass_missing_or_modified_sibling_checks() {
        const FILES: &[ComponentFile] = &[
            TEST_FILE,
            ComponentFile {
                relative_path: "test/helper.dll",
                sha256: TEST_FILE.sha256,
                size_bytes: TEST_FILE.size_bytes,
            },
        ];
        let dir = Fixture::new();
        let component = OptionalComponent {
            id: "test",
            version: "1",
            files: FILES,
        };
        std::fs::write(dir.0.join("helper.exe"), b"hello").unwrap();
        assert!(verified_flat_directory(&component, &dir.0).is_none());
        std::fs::write(dir.0.join("helper.dll"), b"hello").unwrap();
        assert_eq!(
            verified_flat_directory(&component, &dir.0).unwrap().len(),
            2
        );
        std::fs::write(dir.0.join("helper.dll"), b"other").unwrap();
        assert!(verified_flat_directory(&component, &dir.0).is_none());
    }

    #[test]
    fn failed_component_promotion_restores_the_existing_directory() {
        let dir = Fixture::new();
        let root = dir.0.join("live");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("keep"), b"existing component").unwrap();
        let missing = dir.0.join("missing.staging");
        assert!(promote(&missing, &root).is_err());
        assert_eq!(
            std::fs::read(root.join("keep")).unwrap(),
            b"existing component"
        );
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
        let staging = Staging::create(&root).unwrap();
        std::fs::write(staging.path.join("new"), b"new component").unwrap();
        promote(&staging.path, &root).unwrap();
        drop(staging);
        assert_eq!(std::fs::read(root.join("new")).unwrap(), b"new component");
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn cancelled_component_work_cleans_only_its_own_staging_directory() {
        let dir = Fixture::new();
        let root = dir.0.join("live");
        let unrelated = dir.0.join("previous.staging");
        std::fs::create_dir(&unrelated).unwrap();
        let (ready, started) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let staging = Staging::create(&root).unwrap();
            ready.send(staging.path.clone()).unwrap();
            std::future::pending::<()>().await;
            drop(staging);
        });
        let owned = started.await.unwrap();
        assert!(owned.exists());
        task.abort();
        let _ = task.await;
        assert!(!owned.exists());
        assert!(unrelated.exists());
    }

    /// The files as they still sit in the desktop crate, which is what gets
    /// uploaded to the component host.
    fn repo_component_dir() -> PathBuf {
        // CI prepares the pinned upstream archive outside the checkout.
        // This override is compiled only into tests, never the client.
        if let Some(path) = std::env::var_os("SWIFTTUNNEL_TEST_COMPONENT_DIR") {
            return PathBuf::from(path);
        }
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("swifttunnel-desktop")
            .join("src-tauri")
            .join("resources")
            .join("tools")
            .join("goodbyedpi")
    }

    #[test]
    fn pinned_hashes_match_the_files_we_actually_ship() {
        // The whole design rests on these hashes being the real ones. If a file
        // is ever replaced without repinning, this fails here rather than
        // silently refusing to install on every user's machine at once.
        for arch in [ComponentArch::X64, ComponentArch::X86] {
            let component = goodbyedpi_component(arch);
            for file in component.files {
                let path = repo_component_dir().join(file.relative_path);
                let bytes = std::fs::read(&path)
                    .unwrap_or_else(|e| panic!("missing {}: {e}", path.display()));

                assert_eq!(
                    bytes.len() as u64,
                    file.size_bytes,
                    "size drifted for {}",
                    file.relative_path
                );
                assert_eq!(
                    sha256_of(&bytes),
                    file.sha256,
                    "hash drifted for {}",
                    file.relative_path
                );
            }
        }
    }

    #[test]
    fn every_arch_brings_its_executable() {
        for arch in [ComponentArch::X64, ComponentArch::X86] {
            let component = goodbyedpi_component(arch);
            assert!(
                component
                    .files
                    .iter()
                    .any(|f| f.relative_path.ends_with("goodbyedpi.exe")),
                "{arch:?} has no goodbyedpi.exe"
            );
        }
    }

    #[test]
    fn the_32_bit_payload_carries_both_drivers() {
        // GoodbyeDPI 32-bit picks its driver by OS bitness at runtime, so
        // shipping one of the two breaks half the machines that need it.
        let files = goodbyedpi_component(ComponentArch::X86).files;
        assert!(
            files
                .iter()
                .any(|f| f.relative_path.ends_with("WinDivert32.sys"))
        );
        assert!(
            files
                .iter()
                .any(|f| f.relative_path.ends_with("WinDivert64.sys"))
        );
    }

    #[test]
    fn install_path_is_versioned() {
        // Two versions must never share a directory, or an upgrade can leave a
        // mix of old and new files that passes a per-file check.
        let component = goodbyedpi_component(ComponentArch::X64);
        let dir = component_dir(&component);
        assert!(dir.ends_with(GOODBYEDPI_VERSION));
        assert!(dir.to_string_lossy().contains("goodbyedpi"));
    }

    #[test]
    fn urls_are_https_and_versioned() {
        let component = goodbyedpi_component(ComponentArch::X64);
        let url = file_url(&component, &component.files[0]);
        assert!(url.starts_with("https://"), "component fetch must be TLS");
        assert!(url.contains(GOODBYEDPI_VERSION));
        assert!(url.ends_with("x86_64/goodbyedpi.exe"));
    }

    #[test]
    fn a_missing_component_is_not_reported_as_installed() {
        let absent = OptionalComponent {
            id: "does-not-exist",
            version: "0",
            files: GOODBYEDPI_X64_FILES,
        };
        assert!(!is_installed(&absent));
    }

    #[test]
    fn only_network_failures_are_worth_retrying() {
        assert!(
            ComponentError::HttpStatus {
                url: "u".into(),
                status: 503
            }
            .is_transient()
        );
        // Retrying these just re-downloads the same bytes into the same wall.
        assert!(!ComponentError::Quarantined { file: "f".into() }.is_transient());
        assert!(
            !ComponentError::HashMismatch {
                file: "f".into(),
                expected: "a".into(),
                actual: "b".into()
            }
            .is_transient()
        );
    }
}
