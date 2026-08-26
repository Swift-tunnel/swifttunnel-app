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

use std::path::{Path, PathBuf};

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

fn sha256_of_file(path: &Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(sha256_of(&bytes))
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
        match std::fs::metadata(&path) {
            Ok(meta) if meta.len() == file.size_bytes => sha256_of_file(&path)
                .map(|h| h == file.sha256)
                .unwrap_or(false),
            _ => false,
        }
    })
}

/// The installed executable for a component file, if the component is intact.
pub fn installed_path(component: &OptionalComponent, relative_path: &str) -> Option<PathBuf> {
    let path = component_dir(component).join(relative_path);
    path.exists().then_some(path)
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
    let root = component_dir(component);
    if is_installed(component) {
        return Ok(root);
    }

    let staging = root.with_file_name(format!("{}.staging", component.version));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|source| ComponentError::Io {
        context: format!("could not create {}", staging.display()),
        source,
    })?;

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

        let bytes = response
            .bytes()
            .await
            .map_err(|source| ComponentError::Download {
                url: url.clone(),
                reason: source.to_string(),
            })?;

        let actual = sha256_of(&bytes);
        if actual != file.sha256 {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(ComponentError::HashMismatch {
                file: file.relative_path.to_string(),
                expected: file.sha256.to_string(),
                actual,
            });
        }

        let dest = staging.join(file.relative_path);
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
    let _ = std::fs::remove_dir_all(&root);
    if let Some(parent) = root.parent() {
        std::fs::create_dir_all(parent).map_err(|source| ComponentError::Io {
            context: format!("could not create {}", parent.display()),
            source,
        })?;
    }
    std::fs::rename(&staging, &root).map_err(|source| ComponentError::Io {
        context: format!("could not move {} into place", staging.display()),
        source,
    })?;

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

#[cfg(test)]
mod tests {
    use super::*;

    /// The files as they still sit in the desktop crate, which is what gets
    /// uploaded to the component host.
    fn repo_component_dir() -> PathBuf {
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
