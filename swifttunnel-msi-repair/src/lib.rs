//! Clearing an orphaned SwiftTunnel MSI registration.
//!
//! # The problem this exists for
//!
//! An MSI major upgrade removes the old version before installing the new one,
//! and to do that Windows Installer needs the *original* .msi the old version
//! was installed from. It keeps a copy under `C:\Windows\Installer` for exactly
//! this, and falls back to the path the package was installed from.
//!
//! Users who run PC cleanup utilities lose the cached copy, and the fallback
//! path is usually gone too: it was either a Downloads folder they tidied, or
//! the auto-updater's temp directory, which Windows wipes on its own. With
//! neither available the upgrade stops on:
//!
//!   "The feature you are trying to use is on a network resource that is
//!    unavailable"
//!
//! The install is then unwinnable from the UI. Windows still believes
//! SwiftTunnel is installed, so a fresh install turns into an upgrade and hits
//! the same wall, and uninstalling fails for the same reason.
//!
//! # Why this is a library
//!
//! Setup and the app updaters call this library before launching msiexec.
//! Their broader recovery runs elevated. The Desktop MSI now uses a separate,
//! scoped DLL in `swifttunnel-msi-actions`: an early InstallExecute flush runs
//! recovery as SYSTEM before RemoveExistingProducts and before new files land.
//! It handles confirmed missing per-machine Desktop packages only. The launcher
//! remains useful for other orphan cases. Neither approach is a full uninstall.

use std::path::Path;

use windows_registry::{CURRENT_USER, LOCAL_MACHINE};

/// Where Windows records per-machine installed products.
/// Every account's installed-product list, not just the machine account's.
///
/// This used to point straight at `S-1-5-18`, the machine account, which is
/// where a per-machine install registers. An install done per-user registers
/// under that user's own SID instead and was invisible here, so the repair
/// reported a healthy machine and the upgrade failed anyway.
const USERDATA: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData";
const CLASSES_PRODUCTS: &str = r"SOFTWARE\Classes\Installer\Products";
const CLASSES_FEATURES: &str = r"SOFTWARE\Classes\Installer\Features";
const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

fn is_client_name(name: &str) -> bool {
    ["SwiftTunnel", "SwiftTunnel Lite"]
        .iter()
        .any(|expected| name.trim().eq_ignore_ascii_case(expected))
}

#[derive(Debug, Clone)]
pub struct Orphan {
    /// Which account's product list this was found under.
    pub sid: String,
    /// Registry-form (packed) product id, as used by the Installer keys.
    pub packed: String,
    /// Human product code, `{XXXXXXXX-....}`, as used by the Uninstall key.
    pub product_code: String,
    pub display_name: String,
    pub display_version: String,
    pub local_package: String,
}

/// Every SwiftTunnel registration on the machine, healthy or not.
///
/// Shared by the two halves of this crate: the repair wants the ones whose
/// package has gone, and the source preservation wants the ones whose package
/// is still there.
fn all_registrations() -> windows_registry::Result<Vec<(Orphan, bool)>> {
    let userdata = LOCAL_MACHINE.open(USERDATA)?;
    let mut out = Vec::new();

    for sid in userdata.keys()? {
        let Ok(products) = userdata.open(format!(r"{sid}\Products")) else {
            continue;
        };
        let Ok(packed_keys) = products.keys() else {
            continue;
        };

        for packed in packed_keys {
            let Ok(props) = products.open(format!(r"{packed}\InstallProperties")) else {
                continue;
            };

            let display_name = props.get_string("DisplayName").unwrap_or_default();
            let product_code = unpack_guid(&packed);
            if !is_client_name(&display_name) || product_code.is_empty() {
                continue;
            }

            // An unreadable or missing value does not establish that the file
            // is missing. In particular, never turn a query failure into an
            // empty path that authorizes removing a registration.
            let Ok(local_package) = props.get_string("LocalPackage") else {
                continue;
            };
            let usable = package_is_usable(&local_package);

            out.push((
                Orphan {
                    sid: sid.clone(),
                    product_code,
                    packed,
                    display_name,
                    display_version: props.get_string("DisplayVersion").unwrap_or_default(),
                    local_package,
                },
                usable,
            ));
        }
    }

    Ok(out)
}

/// SwiftTunnel registrations whose cached installer package no longer exists.
///
/// A registration whose package is still on disk is healthy and is skipped, so
/// running this on a working machine finds nothing and changes nothing.
pub fn find_orphans() -> windows_registry::Result<Vec<Orphan>> {
    Ok(all_registrations()?
        .into_iter()
        .filter(|(_, usable)| !usable)
        .map(|(orphan, _)| orphan)
        .collect())
}

/// Whether two files hold identical bytes.
///
/// Streamed rather than read whole, because installer packages run to tens of
/// megabytes and this walks every installed product. Length is checked first
/// since it settles almost every case for free.
///
/// Any error is "not the same". Being unable to read one of them is not
/// evidence they match. A mismatch leaves the registered source unchanged;
/// the shared cache never overwrites an existing MSI.
fn files_have_same_contents(left: &Path, right: &Path) -> bool {
    use std::io::Read;

    let (Ok(left_meta), Ok(right_meta)) = (std::fs::metadata(left), std::fs::metadata(right))
    else {
        return false;
    };
    if left_meta.len() != right_meta.len() {
        return false;
    }

    let (Ok(left_file), Ok(right_file)) = (std::fs::File::open(left), std::fs::File::open(right))
    else {
        return false;
    };

    let mut left_reader = std::io::BufReader::new(left_file);
    let mut right_reader = std::io::BufReader::new(right_file);
    let mut left_chunk = [0u8; 64 * 1024];
    let mut right_chunk = [0u8; 64 * 1024];

    loop {
        let read = match left_reader.read(&mut left_chunk) {
            Ok(0) => return true,
            Ok(read) => read,
            Err(_) => return false,
        };
        if right_reader.read_exact(&mut right_chunk[..read]).is_err() {
            return false;
        }
        if left_chunk[..read] != right_chunk[..read] {
            return false;
        }
    }
}

/// Whether the cached package is one Windows Installer could actually use.
///
/// Existing is not the same as usable. Cleanup tools truncate files as often as
/// they delete them, and a zero-length or half-written package passes a plain
/// existence check while Windows still refuses it and asks for the original,
/// which is the failure this whole crate exists to prevent.
///
/// An MSI is an OLE compound document, so the first eight bytes are a fixed
/// signature. Checking them costs one short read and rules out both an empty
/// file and something that is not a package at all.
///
/// Only a package we can prove is bad counts as bad. Saying "not usable" gets a
/// registration deleted, and this now runs on every launch rather than only
/// when someone is already installing, so the cost of being wrong changed. A
/// file we cannot read is not evidence of anything: `C:\Windows\Installer` is
/// readable only by SYSTEM and administrators, and antivirus holds a package
/// open often enough to deny a share. Both look identical to a deleted file
/// through `exists()`, which reports false when metadata is denied. Treating
/// either as missing would unregister a perfectly healthy install, silently, on
/// a machine where nothing was ever wrong.
///
/// Note what this does *not* establish: an OLE signature is common to every MSI
/// ever made, so a valid package that is not ours passes it. Deciding that a
/// file is the *right* package is `files_have_same_contents`, and
/// `preserve_installer_sources` needs both for that reason.
fn package_is_usable(path: &str) -> bool {
    if !local_source_path(Path::new(path)) {
        // Unknown location, not proof that a local cached package is missing.
        // Do not contact a network share from elevated startup maintenance.
        return true;
    }

    // Absent is the one thing worth acting on. Anything else that stops us
    // looking is unknown, and unknown must leave the registration alone.
    match std::fs::metadata(Path::new(path)) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return true,
    }

    match std::fs::File::open(path) {
        Ok(file) => package_header_is_usable(file),
        // It is there but we cannot open it. That is a lock or an ACL, not a
        // missing package, so assume the installer will manage.
        Err(_) => true,
    }
}

fn package_header_is_usable(mut file: impl std::io::Read) -> bool {
    const OLE_SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    let mut head = [0u8; 8];
    match file.read_exact(&mut head) {
        Ok(()) => head == OLE_SIGNATURE,
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => false,
        // A read failure after opening the file is still unknown state. Never
        // authorize unregistering a product because of a transient I/O failure.
        Err(_) => true,
    }
}

/// Remove every key that makes Windows believe the product is installed.
pub fn clear_registration(orphan: &Orphan) -> Result<(), String> {
    validate_orphan(orphan)?;
    // Discovery can precede a long source-preservation pass. Recheck the
    // registration before any deletion; a recovered package is no orphan.
    let props = LOCAL_MACHINE
        .open(format!(
            r"{USERDATA}\{}\Products\{}\InstallProperties",
            orphan.sid, orphan.packed
        ))
        .map_err(|error| {
            format!(
                "Could not recheck the installer registration: {error}. Reopen the repair tool."
            )
        })?;
    let name = props
        .get_string("DisplayName")
        .map_err(|error| format!("Could not recheck the product name: {error}"))?;
    let package = props
        .get_string("LocalPackage")
        .map_err(|error| format!("Could not recheck the installer source: {error}"))?;
    if !name.trim().eq_ignore_ascii_case(orphan.display_name.trim())
        || package != orphan.local_package
    {
        return Err("The installation changed while it was being checked. Reopen the repair tool before trying again.".into());
    }
    if package_is_usable(&package) {
        return Err("Windows no longer confirms that this installer source is missing. No registration was removed. Reopen Setup to continue.".into());
    }
    drop(props);
    // Classes/Installer keys are shared by product code. Do not remove them
    // while another account still has a registration for that same product.
    let users = LOCAL_MACHINE
        .open(USERDATA)
        .map_err(|error| format!("Could not check other Windows installations: {error}"))?;
    for (index, sid) in users.keys().map_err(|error| error.to_string())?.enumerate() {
        if index >= 256 {
            return Err(
                "Too many Windows account records to confirm a safe repair. Contact support."
                    .into(),
            );
        }
        if sid == orphan.sid {
            continue;
        }
        match users.open(format!(r"{sid}\Products\{}", orphan.packed)) {
            Ok(_) => return Err("Another Windows account still has this SwiftTunnel version registered. Its shared installer information was left intact. Use Windows Settings > Apps to repair the affected copy.".into()),
            Err(error) if registry_not_found(error.code().0 as u32) => {}
            Err(error) => return Err(format!("Could not check another Windows account's installer registration: {error}. Nothing was removed.")),
        }
    }
    clear_registration_with(
        orphan,
        |hive, path| {
            hive.key()
                .remove_tree(path)
                .map_err(|error| error.code().0 as u32)
        },
        |hive, path| match hive.key().open(path) {
            Ok(_) => Ok(false),
            Err(error) if registry_not_found(error.code().0 as u32) => Ok(true),
            Err(error) => Err(error.code().0 as u32),
        },
    )
}

fn validate_orphan(orphan: &Orphan) -> Result<(), String> {
    let valid_sid = orphan.sid.starts_with("S-1-")
        && orphan.sid.len() <= 184
        && orphan.sid.split('-').skip(2).count() >= 2
        && orphan
            .sid
            .split('-')
            .skip(2)
            .all(|part| !part.is_empty() && part.bytes().all(|c| c.is_ascii_digit()));
    let code = unpack_guid(&orphan.packed);
    if !valid_sid
        || !is_client_name(&orphan.display_name)
        || code.is_empty()
        || !code.eq_ignore_ascii_case(&orphan.product_code)
    {
        return Err(
            "The repair record does not identify a SwiftTunnel installation. Nothing was removed."
                .into(),
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum RegistrationHive {
    Machine,
    User,
}
impl RegistrationHive {
    fn key(self) -> &'static windows_registry::Key {
        match self {
            Self::Machine => LOCAL_MACHINE,
            Self::User => CURRENT_USER,
        }
    }
}

fn registry_not_found(code: u32) -> bool {
    matches!(code, 0x80070002 | 0x80070003)
}

fn clear_registration_with(
    orphan: &Orphan,
    mut remove: impl FnMut(RegistrationHive, &str) -> Result<(), u32>,
    mut absent: impl FnMut(RegistrationHive, &str) -> Result<bool, u32>,
) -> Result<(), String> {
    validate_orphan(orphan)?;
    // Keep the discovery record until the other deletions succeed. An access
    // failure must remain diagnosable and retryable, not look like success.
    let paths = [
        (
            RegistrationHive::Machine,
            format!(r"{CLASSES_PRODUCTS}\{}", orphan.packed),
        ),
        (
            RegistrationHive::Machine,
            format!(r"{CLASSES_FEATURES}\{}", orphan.packed),
        ),
        (
            RegistrationHive::Machine,
            format!(r"{UNINSTALL}\{}", orphan.product_code),
        ),
        (
            RegistrationHive::User,
            format!(r"{UNINSTALL}\{}", orphan.product_code),
        ),
        (
            RegistrationHive::Machine,
            format!(r"{USERDATA}\{}\Products\{}", orphan.sid, orphan.packed),
        ),
    ];
    for (index, (hive, path)) in paths.iter().enumerate() {
        if index == paths.len() - 1 {
            // Confirm secondary records before discarding our retry anchor.
            for (hive, path) in &paths[..index] {
                if !matches!(absent(*hive, path), Ok(true)) {
                    return Err("Could not confirm the partial installer repair. The installation record was kept so you can retry as administrator.".into());
                }
            }
        }
        if let Err(error) = remove(*hive, path) {
            if !registry_not_found(error) {
                return Err(format!("Installer registration repair is incomplete (Windows error 0x{error:08X}). Reopen the repair tool as administrator to retry."));
            }
        }
    }
    for (hive, path) in &paths {
        match absent(*hive, path) {
            Ok(true) => {}
            _ => return Err("Could not confirm that the installer registration was removed. Reopen the repair tool as administrator to retry.".into()),
        }
    }
    Ok(())
}

/// Find and clear every orphaned registration, returning what was cleared.
///
/// A no-op on a healthy machine, so callers can run it unconditionally before
/// an install rather than trying to detect the broken state themselves.
pub fn repair() -> Result<Vec<Orphan>, String> {
    let orphans =
        find_orphans().map_err(|e| format!("could not read the installer registry: {e}"))?;
    for orphan in &orphans {
        clear_registration(orphan)?;
    }
    Ok(orphans)
}

/// Convert a packed installer id back into a readable product code.
///
/// Windows stores product codes with the first three GUID fields byte-reversed
/// and the remaining eight bytes nibble-swapped, which is why these keys look
/// like nonsense next to the GUID they represent. The Uninstall key uses the
/// readable form, so both are needed to clean up fully.
pub fn unpack_guid(packed: &str) -> String {
    if packed.len() != 32 || !packed.chars().all(|c| c.is_ascii_hexdigit()) {
        return String::new();
    }
    let b = packed.as_bytes();
    let rev = |from: usize, len: usize| -> String {
        (0..len).rev().map(|i| b[from + i] as char).collect()
    };
    let swap_pairs = |from: usize, len: usize| -> String {
        (0..len)
            .step_by(2)
            .flat_map(|i| [b[from + i + 1] as char, b[from + i] as char])
            .collect()
    };

    format!(
        "{{{}-{}-{}-{}-{}}}",
        rev(0, 8),
        rev(8, 4),
        rev(12, 4),
        swap_pairs(16, 4),
        swap_pairs(20, 12),
    )
}

#[cfg(test)]
mod tests {
    fn orphan() -> super::Orphan {
        super::Orphan {
            sid: "S-1-5-18".into(),
            packed: "D128028F38FA27944BA0B4B4D4359AE2".into(),
            product_code: "{F820821D-AF83-4972-B40A-4B4B4D53A92E}".into(),
            display_name: "SwiftTunnel".into(),
            display_version: "3.0.4".into(),
            local_package: "C:\\owned-fixture\\missing.msi".into(),
        }
    }

    #[test]
    fn incomplete_cleanup_keeps_discovery_until_secondary_removals_succeed() {
        let mut removed = vec![];
        let result = super::clear_registration_with(
            &orphan(),
            |_, path| {
                removed.push(path.to_string());
                if removed.len() == 2 {
                    Err(0x80070005)
                } else {
                    Ok(())
                }
            },
            |_, _| panic!("a failed deletion cannot be reported as verified"),
        );
        assert!(result.unwrap_err().contains("incomplete"));
        assert_eq!(removed.len(), 2);
        assert!(!removed.iter().any(|path| path.contains("UserData")));

        removed.clear();
        super::clear_registration_with(
            &orphan(),
            |_, path| {
                removed.push(path.to_string());
                Err(0x80070002) // An already removed key is retryable.
            },
            |_, _| Ok(true),
        )
        .unwrap();
        assert_eq!(removed.len(), 5);
        assert!(removed.last().unwrap().contains("UserData"));
    }

    #[test]
    fn cleanup_verification_never_treats_access_errors_or_remaining_keys_as_absence() {
        for verified in [Ok(false), Err(0x80070005)] {
            let mut removed = vec![];
            let result = super::clear_registration_with(
                &orphan(),
                |_, path| {
                    removed.push(path.to_string());
                    Ok(())
                },
                |_, _| verified,
            );
            assert!(result.unwrap_err().contains("Could not confirm"));
            assert!(!removed.iter().any(|path| path.contains("UserData")));
        }
    }

    #[test]
    fn cleanup_admits_only_exact_client_names_and_consistent_leaf_identifiers() {
        for name in ["SwiftTunnel", "swifttunnel lite", " SwiftTunnel "] {
            let mut record = orphan();
            record.display_name = name.into();
            assert!(super::validate_orphan(&record).is_ok());
        }
        for (field, value) in [
            ("name", "NotSwiftTunnel"),
            ("name", "SwiftTunnel Tools"),
            ("packed", "not-a-guid"),
            ("packed", "..\\other"),
            ("sid", "S-1-5-18\\other"),
            ("sid", "S-1--18"),
            ("product", "{5EC81BE0-A95C-40A1-A761-C4846CED3900}"),
        ] {
            let mut record = orphan();
            match field {
                "name" => record.display_name = value.into(),
                "packed" => record.packed = value.into(),
                "sid" => record.sid = value.into(),
                _ => record.product_code = value.into(),
            }
            assert!(super::clear_registration_with(
                &record,
                |_, _| panic!("invalid identifiers must not reach registry removal"),
                |_, _| panic!("invalid identifiers must not reach registry reads"),
            )
            .is_err());
        }
    }

    use super::{
        files_have_same_contents, package_header_is_usable, package_is_usable, unpack_guid,
    };

    #[test]
    fn package_read_errors_are_unknown_not_evidence_of_a_broken_installer() {
        struct Unreadable(std::io::ErrorKind);
        impl std::io::Read for Unreadable {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    self.0,
                    "simulated package read failure",
                ))
            }
        }
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::TimedOut,
            std::io::ErrorKind::Other,
        ] {
            assert!(
                package_header_is_usable(Unreadable(kind)),
                "{kind:?} must not authorize orphan cleanup"
            );
        }
        assert!(!package_header_is_usable(Unreadable(
            std::io::ErrorKind::UnexpectedEof
        )));
        assert!(!package_header_is_usable(&b"not msi!"[..]));
        assert!(package_header_is_usable(&OLE[..]));
    }

    #[test]
    fn oversized_sources_are_not_read_and_exact_limit_sources_remain_byte_exact() {
        let path = std::env::temp_dir().join(format!(
            "swift-source-bound-{}-{}.msi",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let bytes = [0xAB; 33];
        std::fs::write(&path, bytes).unwrap();
        let too_large = super::read_source_file_bounded(&path, 32);
        let exact = super::read_source_file_bounded(&path, 33);
        let source = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(too_large.is_err());
        assert_eq!(exact.unwrap(), bytes);
        assert_eq!(source, bytes);
    }

    /// A preserved copy is reused only when it really is the same package.
    ///
    /// This compared lengths, and the signature check beside it passes for any
    /// valid MSI, so between them they could not tell this product's package
    /// from anybody else's. The destination sits under ProgramData, named after
    /// a product code any user can read from the registry, so a same-length
    /// package left there in advance would have been kept and then written into
    /// the registry as the install source Windows trusts for every later repair
    /// and upgrade.
    #[test]
    fn a_same_length_package_is_not_treated_as_the_same_package() {
        let dir = std::env::temp_dir().join(format!(
            "swifttunnel-preserve-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source.msi");
        let destination = dir.join("destination.msi");

        std::fs::write(&source, b"the real package").unwrap();

        std::fs::write(&destination, b"the real package").unwrap();
        assert!(
            files_have_same_contents(&source, &destination),
            "an identical copy must be recognised, or every run recopies it"
        );

        // Same length, different bytes: the planted case.
        std::fs::write(&destination, b"the fake package").unwrap();
        assert_eq!(
            std::fs::metadata(&source).unwrap().len(),
            std::fs::metadata(&destination).unwrap().len()
        );
        assert!(
            !files_have_same_contents(&source, &destination),
            "a same-length impostor must not be mistaken for the real package"
        );

        // Different length, and a missing file, are both mismatches.
        std::fs::write(&destination, b"short").unwrap();
        assert!(!files_have_same_contents(&source, &destination));
        std::fs::remove_file(&destination).unwrap();
        assert!(!files_have_same_contents(&source, &destination));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Chunked comparison must not stop at the first block.
    ///
    /// Packages run to tens of megabytes, so the comparison streams. A
    /// difference past the first chunk is exactly what a padded impostor would
    /// rely on.
    #[test]
    fn a_difference_after_the_first_chunk_is_still_found() {
        let dir = std::env::temp_dir().join(format!(
            "swifttunnel-preserve-chunk-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source.msi");
        let destination = dir.join("destination.msi");

        let mut bytes = vec![0xABu8; 200 * 1024];
        std::fs::write(&source, &bytes).unwrap();

        // Identical except for one byte well past the 64KB read size.
        bytes[150 * 1024] = 0xCD;
        std::fs::write(&destination, &bytes).unwrap();

        assert!(
            !files_have_same_contents(&source, &destination),
            "a difference beyond the first chunk must still be caught"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Taken from a real SwiftTunnel 3.0.4 install, so the transformation is
    /// pinned against an actual Windows-generated key rather than my reading of
    /// the format.
    #[test]
    fn unpacks_a_real_product_code() {
        assert_eq!(
            unpack_guid("D128028F38FA27944BA0B4B4D4359AE2"),
            "{F820821D-AF83-4972-B40A-4B4B4D53A92E}"
        );
    }

    #[test]
    fn rejects_anything_that_is_not_a_packed_guid() {
        assert_eq!(unpack_guid(""), "");
        assert_eq!(unpack_guid("not-a-guid"), "");
        // Right length, wrong alphabet.
        assert_eq!(unpack_guid("Z128028F38FA27944BA0B4B4D4359AE2"), "");
    }

    const OLE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    fn temp_file(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        use std::io::Write;
        let path = std::env::temp_dir().join(format!("swifttunnel-repair-test-{name}"));
        let mut file = std::fs::File::create(&path).expect("create temp file");
        file.write_all(bytes).expect("write temp file");
        path
    }

    #[test]
    fn a_real_package_is_usable() {
        let mut bytes = OLE.to_vec();
        bytes.extend_from_slice(&[0u8; 512]);
        let path = temp_file("good.msi", &bytes);
        assert!(package_is_usable(path.to_str().unwrap()));
        let _ = std::fs::remove_file(path);
    }

    /// A package we are not allowed to read must not be called missing.
    ///
    /// This decides whether a registration gets deleted, and it now runs on
    /// every launch rather than only when someone is installing. The real
    /// cached packages live in `C:\Windows\Installer`, which only SYSTEM and
    /// administrators can read, and antivirus takes an exclusive handle on
    /// them often enough to matter. Answering "missing" to either would
    /// unregister a healthy install on a machine where nothing was wrong.
    #[cfg(windows)]
    #[test]
    fn a_package_we_cannot_open_is_left_alone() {
        use std::os::windows::fs::OpenOptionsExt;

        let mut bytes = OLE.to_vec();
        bytes.extend_from_slice(&[0u8; 512]);
        let path = temp_file("locked.msi", &bytes);

        // share_mode(0) denies every other open, which is exactly the
        // sharing violation a scanner produces.
        let locked = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            .expect("take an exclusive handle");

        assert!(
            package_is_usable(path.to_str().unwrap()),
            "a locked package must be treated as present, not deleted"
        );

        drop(locked);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_truncated_package_is_not() {
        // The case that made this necessary. Cleanup tools truncate as often
        // as they delete, and the old check only asked whether the path
        // existed, so a nine byte file counted as a healthy install while
        // Windows still refused it and demanded the original.
        let path = temp_file("truncated.msi", b"broken");
        assert!(!package_is_usable(path.to_str().unwrap()));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn an_empty_package_is_not() {
        let path = temp_file("empty.msi", b"");
        assert!(!package_is_usable(path.to_str().unwrap()));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn something_that_is_not_a_package_is_not() {
        // Right length, wrong contents.
        let path = temp_file("wrong.msi", &[0u8; 4096]);
        assert!(!package_is_usable(path.to_str().unwrap()));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_missing_local_package_is_distinct_from_an_unknown_location() {
        assert!(package_is_usable(""));
        assert!(!package_is_usable("C:/definitely/not/here/nope.msi"));
    }

    #[test]
    fn unknown_installer_paths_are_kept_and_rejected_before_source_reads() {
        use std::path::Path;
        for path in [
            "",
            "relative.msi",
            "C:relative.msi",
            r"\\unreachable.invalid\share\source.msi",
            r"\\?\UNC\unreachable.invalid\share\source.msi",
            r"\\.\pipe\source",
            r"C:\source.msi:stream",
            r"C:\folder\..\source.msi",
        ] {
            assert!(!super::local_source_path(Path::new(path)), "{path}");
            assert!(
                package_is_usable(path),
                "unknown is not a missing package: {path}"
            );
            assert_eq!(
                super::read_source_file_bounded(Path::new(path), 32)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
        for path in [
            r"E:\Windows\Installer\source.msi",
            r"\\?\E:\Windows\Installer\source.msi",
            "C:/Windows/Installer/source.msi",
        ] {
            assert!(super::local_source_path(Path::new(path)), "{path}");
        }
    }
}

/// Keep a copy of every installed product's package, and point Windows at it.
///
/// This is the prevention that makes the repair rarely needed. Windows keeps
/// the package under `C:\Windows\Installer` and falls back to the recorded
/// install source when that copy is deleted, which is exactly what PC cleanup
/// tools do. The fallback then decides whether an upgrade works, and it usually
/// points at a Downloads folder the user has since tidied or a temp directory
/// Windows itself wiped.
///
/// So while the cached package is still healthy, copy it somewhere durable and
/// repoint the source at that copy. A later cleanup then costs nothing: the
/// fallback resolves, the upgrade proceeds, and the user never sees "the
/// feature you are trying to use is on a network resource that is unavailable".
///
/// Unlike the staging in `swifttunnel-setup`, this does not care how the
/// product was installed. It runs after the fact, so it covers the .msi
/// downloaded straight from the site just as well as the launcher.
///
/// Best effort throughout, and deliberately timid: a source that already works
/// is only ever replaced by a copy that has been verified as a real package.
/// Pointing Windows at a bad file breaks upgrades exactly as thoroughly as
/// pointing it at a missing one, so a failure here leaves the registry alone.
pub fn preserve_installer_sources() -> Result<Vec<String>, String> {
    let cache = swifttunnel_installer_cache::InstallerCache::open().map_err(|e| e.to_string())?;
    let mut preserved = Vec::new();

    for (product, usable) in all_registrations().map_err(|e| e.to_string())? {
        // Nothing to copy from. This one is the repair's problem, not ours.
        if !usable || product.product_code.is_empty() {
            continue;
        }

        // The product code changes with every release, so each version's
        // package gets its own name and no upgrade overwrites the package an
        // older product still points at.
        let file_name = format!(
            "{}.msi",
            product.product_code.trim_matches(|c| c == '{' || c == '}')
        );
        // Copy from a readable registered package, then hold the verified
        // protected copy while checking the OLE header and updating SourceList.
        let Ok(bytes) =
            read_source_file_bounded(Path::new(&product.local_package), 256 * 1024 * 1024)
        else {
            continue;
        };
        let Ok(installer) = cache.stage(&file_name, &bytes) else {
            continue;
        };
        let destination = installer.path();
        if !files_have_same_contents(Path::new(&product.local_package), destination)
            || !package_is_usable(&destination.to_string_lossy())
        {
            continue;
        }
        let Some(dir) = destination.parent() else {
            continue;
        };
        let Some(file_name) = destination.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if point_source_at(&product.packed, dir, file_name).is_ok() {
            preserved.push(format!(
                "{} {}",
                product.display_name, product.display_version
            ));
        }
    }

    Ok(preserved)
}

/// A damaged cached package must not control startup memory consumption.
fn read_source_file_bounded(path: &Path, limit: usize) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, ErrorKind, Read};

    if !local_source_path(path) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Installer source is not a local absolute path",
        ));
    }
    let mut file = std::fs::File::open(path)?;
    if file.metadata()?.len() > limit as u64 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Installer source is too large",
        ));
    }
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        // Also catch a source that grows after the metadata check. Read at
        // most one extra byte, without reserving memory beyond the limit.
        let capacity = buffer.len().min((limit - bytes.len()).saturating_add(1));
        let count = match file.read(&mut buffer[..capacity]) {
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            return Ok(bytes);
        }
        if count > limit - bytes.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Installer source is too large",
            ));
        }
        bytes.try_reserve(count).map_err(Error::other)?;
        bytes.extend_from_slice(&buffer[..count]);
    }
}

fn local_source_path(path: &Path) -> bool {
    use std::path::{Component, Prefix};
    path.is_absolute()
        && matches!(path.components().next(), Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        && path.components().all(|component| match component {
            Component::ParentDir | Component::CurDir => false,
            Component::Normal(value) => !value.to_string_lossy().contains(':'),
            _ => true,
        })
}

/// Record `dir\file_name` as where this product was installed from.
///
/// Three values, because Windows consults them in order and a half-written
/// source list is worse than none: `PackageName` is the file to look for,
/// `Net\1` is the directory to look in, and `LastUsedSource` is the one it
/// tries first.
fn point_source_at(
    packed: &str,
    dir: &std::path::Path,
    file_name: &str,
) -> windows_registry::Result<()> {
    let mut directory = dir.to_string_lossy().to_string();
    if !directory.ends_with('\\') {
        directory.push('\\');
    }

    let source_list = LOCAL_MACHINE.create(format!(r"{CLASSES_PRODUCTS}\{packed}\SourceList"))?;
    source_list.set_string("PackageName", file_name)?;
    // "n" for a network/normal source, then the index into the list below.
    source_list.set_string("LastUsedSource", format!("n;1;{directory}"))?;

    let net = LOCAL_MACHINE.create(format!(r"{CLASSES_PRODUCTS}\{packed}\SourceList\Net"))?;
    net.set_string("1", &directory)?;

    Ok(())
}
