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
    DriverInstall,
}
impl CacheNote {
    fn name(self) -> &'static str {
        match self {
            Self::LiteAttempt => "lite-last-attempt.txt",
            Self::SetupError => "setup-error.txt",
            Self::DriverInstall => "driver-install.log",
        }
    }
}

const MAX_NOTE_BYTES: usize = 16 * 1024;

fn append_note_bytes(previous: &str, message: &str) -> Vec<u8> {
    fn tail(value: &str, budget: usize) -> &str {
        let mut start = value.len().saturating_sub(budget);
        while !value.is_char_boundary(start) {
            start += 1;
        }
        &value[start..]
    }
    // Allocate only the retained tail, even for an unexpectedly long error.
    let message = tail(message, MAX_NOTE_BYTES - 1);
    let previous = tail(previous, MAX_NOTE_BYTES.saturating_sub(message.len() + 2));
    let mut bytes = Vec::with_capacity(previous.len() + message.len() + 2);
    if !previous.is_empty() {
        bytes.extend_from_slice(previous.as_bytes());
        if !previous.ends_with('\n') {
            bytes.push(b'\n');
        }
    }
    bytes.extend_from_slice(message.as_bytes());
    bytes.push(b'\n');
    bytes
}

#[cfg(windows)]
mod platform;
#[cfg(windows)]
pub use platform::{
    windows_installer_path, InstallerCache, ProtectedInstaller, ProtectedWorkspace,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_note_append_keeps_readable_history_and_the_latest_unicode_message() {
        assert_eq!(append_note_bytes("start\n", "ready"), b"start\nready\n");
        assert_eq!(append_note_bytes("start", "ready"), b"start\nready\n");
        let previous = "旧".repeat(MAX_NOTE_BYTES);
        let bytes = append_note_bytes(&previous, "latest 🎮");
        assert!(bytes.len() <= MAX_NOTE_BYTES);
        assert!(std::str::from_utf8(&bytes)
            .unwrap()
            .ends_with("latest 🎮\n"));
        let message = format!("{}latest 🎮", "界".repeat(MAX_NOTE_BYTES));
        let bytes = append_note_bytes("old history", &message);
        assert!(bytes.len() <= MAX_NOTE_BYTES);
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.ends_with("latest 🎮\n"));
        assert!(!text.contains("old history"));
    }
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
