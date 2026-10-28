//! Keep bundled driver staging on the same integrity and file-write path as downloads.

use std::path::Path;
use swifttunnel_core::vpn::winpkfilter::{self, WinpkFilterMsiPackage};

pub(crate) fn stage_driver(
    source: &Path,
    destination: &Path,
    package: &WinpkFilterMsiPackage,
) -> Result<bool, String> {
    swifttunnel_core::roblox_native_launch::safe_path(destination).map_err(|_| {
        "The bundled driver destination is redirected and was left unchanged.".to_string()
    })?;
    if winpkfilter::validate_msi_file(destination, package).is_ok() {
        return Ok(false);
    }
    // Validate the source before creating folders or replacing anything. This
    // is also bounded if a damaged file reports an unexpectedly large size.
    let bytes = winpkfilter::read_validated_msi_file(source, package)?;
    winpkfilter::save_msi_cache(destination, &bytes, package)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    const PACKAGE: WinpkFilterMsiPackage = WinpkFilterMsiPackage {
        arch: winpkfilter::WinpkFilterMsiArch::X64,
        msi_name: "private-fixture.msi",
        asset_name: "private-fixture.msi",
        download_url: "https://example.invalid/private-fixture.msi",
        sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        min_size_bytes: 3,
    };

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "swifttunnel-runtime-asset-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn same_size_corruption_is_replaced_but_a_verified_copy_is_not_rewritten() {
        let fixture = Fixture::new();
        let source = fixture.0.join("source.msi");
        let destination = fixture.0.join("driver.msi");
        fs::write(&source, b"abc").unwrap();
        fs::write(&destination, b"abd").unwrap();
        assert!(stage_driver(&source, &destination, &PACKAGE).unwrap());
        assert_eq!(fs::read(&destination).unwrap(), b"abc");
        let before = fs::metadata(&destination).unwrap().modified().unwrap();
        fs::remove_file(&source).unwrap();
        assert!(!stage_driver(&source, &destination, &PACKAGE).unwrap());
        assert_eq!(
            fs::metadata(&destination).unwrap().modified().unwrap(),
            before
        );
        assert!(!stage_driver(&destination, &destination, &PACKAGE).unwrap());
    }

    #[test]
    fn invalid_source_neither_replaces_existing_data_nor_creates_a_destination_folder() {
        let fixture = Fixture::new();
        let source = fixture.0.join("source.msi");
        let existing = fixture.0.join("keep.msi");
        fs::write(&source, b"abd").unwrap();
        fs::write(&existing, b"keep this").unwrap();
        assert!(stage_driver(&source, &existing, &PACKAGE).is_err());
        assert_eq!(fs::read(&existing).unwrap(), b"keep this");
        let destination = fixture.0.join("missing").join("driver.msi");
        assert!(stage_driver(&source, &destination, &PACKAGE).is_err());
        assert!(!destination.parent().unwrap().exists());
    }

    #[test]
    fn replacing_a_hard_link_preserves_the_other_file() {
        let fixture = Fixture::new();
        let source = fixture.0.join("source.msi");
        let original = fixture.0.join("original.msi");
        let destination = fixture.0.join("driver.msi");
        fs::write(&source, b"abc").unwrap();
        fs::write(&original, b"abd").unwrap();
        fs::hard_link(&original, &destination).unwrap();
        assert!(stage_driver(&source, &destination, &PACKAGE).unwrap());
        assert_eq!(fs::read(original).unwrap(), b"abd");
        assert_eq!(fs::read(destination).unwrap(), b"abc");
    }
}
