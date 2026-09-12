use super::{packed_guid, Result, UPGRADE_CODE};
use windows_registry::Key;

const USERDATA: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products";
const PRODUCTS: &str = r"SOFTWARE\Classes\Installer\Products";
const FEATURES: &str = r"SOFTWARE\Classes\Installer\Features";
const UPGRADES: &str = r"SOFTWARE\Classes\Installer\UpgradeCodes";
const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

fn not_found(code: u32) -> bool {
    // Access denied, invalid data and sharing failures are not absence.
    matches!(code, 0x80070002 | 0x80070003)
}

fn machine_properties(root: &Key, code: &str) -> windows_registry::Result<Key> {
    root.open(format!(
        r"{USERDATA}\{}\InstallProperties",
        packed_guid(code)
    ))
}

pub(super) fn is_desktop_machine_product(root: &Key, code: &str) -> bool {
    let Ok(props) = machine_properties(root, code) else {
        return false;
    };
    if props.get_string("DisplayName").ok().as_deref() != Some("SwiftTunnel")
        || props.get_string("Publisher").ok().as_deref() != Some("SwiftTunnel")
    {
        return false;
    }
    // Do not trust a caller-controlled related-products property alone. Confirm
    // membership in the original Desktop upgrade family in protected HKLM state.
    let Ok(family) = root.open(format!(r"{UPGRADES}\{}", packed_guid(UPGRADE_CODE))) else {
        return false;
    };
    family.get_string(packed_guid(code)).is_ok()
}

fn definitely_missing(path: &str, metadata: impl FnOnce(&str) -> std::io::Result<()>) -> bool {
    // Do not perform SYSTEM filesystem probes against UNC or relative paths.
    let bytes = path.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return false;
    }
    matches!(metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
}

pub(super) fn registration_absent(root: &Key, code: &str) -> bool {
    // All three registration roots must be confirmed absent. This does not
    // mistake an inaccessible registry key for a successful repair.
    [
        format!(r"{USERDATA}\{}", packed_guid(code)),
        format!(r"{PRODUCTS}\{}", packed_guid(code)),
        format!(r"{UNINSTALL}\{code}"),
    ]
    .iter()
    .all(|path| matches!(root.open(path), Err(error) if not_found(error.code().0 as u32)))
}

pub(super) fn repair_missing_package(root: &Key, code: &str) -> Result<bool> {
    if !is_desktop_machine_product(root, code) {
        return Ok(false);
    }
    let path =
        match machine_properties(root, code).and_then(|props| props.get_string("LocalPackage")) {
            Ok(path) => path,
            Err(_) => return Ok(false),
        };
    if !definitely_missing(&path, |path| std::fs::metadata(path).map(|_| ())) {
        return Ok(false);
    }

    // Recovery of an already unusable registration, not an uninstall. As with
    // the preinstall helper, MSI rollback cannot restore these entries. No files,
    // drivers, component registrations or other users are changed. Open all
    // existing parents first. Remove UserData last to allow retry after interruption.
    let packed = packed_guid(code);
    let mut parents = Vec::new();
    for (parent, child) in [
        (PRODUCTS, packed.as_str()),
        (FEATURES, packed.as_str()),
        (UNINSTALL, code),
        (USERDATA, packed.as_str()),
    ] {
        let key = match root.options().read().write().access(0x10000).open(parent) {
            Ok(key) => key,
            Err(error) if not_found(error.code().0 as u32) => continue,
            Err(_) => return Err("cannot open registry recovery parent".into()),
        };
        parents.push((key, child));
    }
    for (key, child) in parents {
        if let Err(error) = key.remove_tree(child) {
            if !not_found(error.code().0 as u32) {
                return Err("cannot remove orphan registration; recovery incomplete".into());
            }
        }
    }
    if !registration_absent(root, code) {
        return Err("registry recovery could not be verified".into());
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    struct Fixture {
        root: Key,
        path: String,
        package: std::path::PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let unique = format!(
                "{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            let path = format!(r"Software\SwiftTunnelMsiActionTests\{unique}");
            Self {
                root: windows_registry::CURRENT_USER.create(&path).unwrap(),
                path,
                package: std::env::temp_dir().join(format!("swift-msi-action-{unique}.msi")),
            }
        }
        fn product(&self, code: &str, name: &str) {
            let packed = packed_guid(code);
            let props = self
                .root
                .create(format!(r"{USERDATA}\{packed}\InstallProperties"))
                .unwrap();
            props.set_string("DisplayName", name).unwrap();
            props.set_string("Publisher", "SwiftTunnel").unwrap();
            props
                .set_string("LocalPackage", self.package.to_str().unwrap())
                .unwrap();
            for path in [
                format!(r"{PRODUCTS}\{packed}"),
                format!(r"{FEATURES}\{packed}"),
                format!(r"{UNINSTALL}\{code}"),
            ] {
                self.root.create(path).unwrap();
            }
            self.root
                .create(format!(r"{UPGRADES}\{}", packed_guid(UPGRADE_CODE)))
                .unwrap()
                .set_string(packed, "")
                .unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = windows_registry::CURRENT_USER.remove_tree(&self.path);
            let _ = std::fs::remove_file(&self.package);
        }
    }
    const OLD: &str = "{F820821D-AF83-4972-B40A-4B4B4D53A92E}";
    const OTHER: &str = "{5EC81BE0-A95C-40A1-A761-C4846CED3900}";

    #[test]
    fn native_registry_fixture_clears_only_the_selected_orphan() {
        // All Installer-shaped paths live below a fresh HKCU test root.
        // No actual installed-product registration is read or modified.
        let fixture = Fixture::new();
        fixture.product(OLD, "SwiftTunnel");
        fixture.product(OTHER, "SwiftTunnel");
        assert!(repair_missing_package(&fixture.root, OLD).unwrap());
        assert!(registration_absent(&fixture.root, OLD));
        assert!(!registration_absent(&fixture.root, OTHER));
        assert!(!repair_missing_package(&fixture.root, OLD).unwrap());
    }

    #[test]
    fn native_registry_fixture_keeps_healthy_lite_and_wrong_family_products() {
        let fixture = Fixture::new();
        fixture.product(OLD, "SwiftTunnel");
        std::fs::write(
            &fixture.package,
            b"existing cached file, validity delegated to MSI",
        )
        .unwrap();
        assert!(!repair_missing_package(&fixture.root, OLD).unwrap());
        std::fs::remove_file(&fixture.package).unwrap();
        fixture.product(OLD, "SwiftTunnel Lite");
        assert!(!repair_missing_package(&fixture.root, OLD).unwrap());
        fixture.product(OLD, "SwiftTunnel");
        fixture
            .root
            .options()
            .read()
            .write()
            .open(format!(r"{UPGRADES}\{}", packed_guid(UPGRADE_CODE)))
            .unwrap()
            .remove_value(packed_guid(OLD))
            .unwrap();
        assert!(!repair_missing_package(&fixture.root, OLD).unwrap());
        assert!(!registration_absent(&fixture.root, OLD));
    }

    #[test]
    fn only_missing_local_packages_authorize_repair() {
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::Other,
            ErrorKind::InvalidInput,
        ] {
            assert!(!definitely_missing(r"C:\Windows\Installer\old.msi", |_| {
                Err(Error::from(kind))
            }));
        }
        assert!(!definitely_missing(
            r"C:\Windows\Installer\old.msi",
            |_| Ok(())
        ));
        assert!(definitely_missing(
            r"C:\Windows\Installer\old.msi",
            |_| Err(Error::from(ErrorKind::NotFound))
        ));
    }

    #[test]
    fn remote_empty_and_relative_paths_are_never_probed_as_system() {
        for path in ["", "old.msi", r"\\server\share\old.msi", r"C:old.msi"] {
            assert!(!definitely_missing(path, |_| panic!(
                "must not probe untrusted path"
            )));
        }
    }
}
