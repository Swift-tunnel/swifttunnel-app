//! Immutable, protected installation sources. No legacy-cache imports or pruning.
//! Existing registrations keep their old sources until repair explicitly repoints
//! them to a verified copy. Public staging accepts bytes already authenticated by
//! the caller; it does not replace update signature verification.

use sha2::{Digest, Sha256};
use std::io;

fn package_name(suggested: &str, bytes: &[u8]) -> io::Result<String> {
    let stem = suggested.strip_suffix(".msi").filter(|s| !s.is_empty());
    if stem.is_none()
        || suggested.len() > 160
        || !suggested
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'+'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid installer file name",
        ));
    }
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Empty installer package",
        ));
    }
    Ok(format!("{}-{:x}.msi", stem.unwrap(), Sha256::digest(bytes)))
}

/// Small non-package records. Their names cannot alias a staged MSI.
#[derive(Clone, Copy)]
pub enum CacheNote {
    LiteAttempt,
    SetupError,
}
impl CacheNote {
    fn name(self) -> &'static str {
        match self {
            Self::LiteAttempt => "lite-last-attempt.txt",
            Self::SetupError => "setup-error.txt",
        }
    }
}

#[cfg(windows)]
mod platform;
#[cfg(windows)]
pub use platform::{windows_installer_path, InstallerCache, ProtectedInstaller};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn package_names_bind_contents_and_reject_paths() {
        assert_eq!(
            package_name("SwiftTunnel-3.1.6.msi", b"one").unwrap(),
            package_name("SwiftTunnel-3.1.6.msi", b"one").unwrap()
        );
        assert_ne!(
            package_name("SwiftTunnel-3.1.6.msi", b"one").unwrap(),
            package_name("SwiftTunnel-3.1.6.msi", b"two").unwrap()
        );
        for name in [
            "../x.msi",
            "..\\x.msi",
            "C:x.msi",
            "a.msi:stream",
            "x.msi ",
            ".msi",
            "x.exe",
        ] {
            assert!(package_name(name, b"one").is_err(), "{name}");
        }
        assert!(package_name("x.msi", b"").is_err());
    }
}
