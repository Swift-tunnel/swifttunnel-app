//! Installer decisions kept independent of Windows and the elevated GUI.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Install,
    Repair,
    Reinstall,
    Uninstall,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Execute(Action),
    DownloadLite,
    UseBundled,
}

pub const LITE_FAMILY: &str = "{9C4E2B77-5A81-4F36-B0D9-1E6A83C7F520}";
pub const DESKTOP_FAMILY: &str = "{E8A8D9AE-1DDB-53D0-BCF4-8268BDDC947D}";

#[derive(Clone, Debug)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub product_code: String,
    pub upgrade_code: String,
}

#[derive(Clone, Debug)]
pub struct Installed {
    pub product_code: String,
    pub version: String,
    pub advertised: bool,
}

#[derive(Debug)]
pub struct RegistrationVersion {
    pub version: String,
    pub advertised: bool,
}

fn registration_error(status: u32) -> String {
    match status {
        1608 => "Windows is missing version information for an existing SwiftTunnel installation. Open Windows Settings > Apps and repair or uninstall that copy, then reopen Setup. If that fails, contact support with code 1608.".into(),
        1618 => "Another installation is running. Wait for it to finish, then reopen Setup.".into(),
        _ => format!("Could not read an existing SwiftTunnel installation (Windows Installer {status}). Reopen Setup. If it persists, contact support with this code."),
    }
}

/// Related-product enumeration includes advertised registrations. VersionString
/// is installed-only; Version is also available for an advertised product.
pub fn registration_version(
    mut property: impl FnMut(&str) -> Result<String, u32>,
    state: impl FnOnce() -> i32,
) -> Result<Option<RegistrationVersion>, String> {
    match property("VersionString") {
        Ok(value) => Ok(Some(RegistrationVersion {
            version: value,
            advertised: false,
        })),
        Err(1605) => Ok(None), // Removed between enumeration and lookup.
        Err(1608) => match state() {
            current_state @ (1 | 5) => {
                let value = match property("Version") {
                    Ok(value) => value,
                    Err(1605) => return Ok(None),
                    Err(error) => return Err(registration_error(error)),
                };
                // MSI's advertised Version encodes major/minor/build in 8/8/16 bits.
                let packed = value.parse::<u32>().map_err(|_| registration_error(1608))?;
                Ok(Some(RegistrationVersion {
                    version: format!("{}.{}.{}", packed >> 24, (packed >> 16) & 0xff, packed & 0xffff),
                    advertised: current_state == 1,
                }))
            }
            -1 => Ok(None), // Neither advertised nor installed anymore.
            2 => Err("SwiftTunnel is registered under another Windows account. Sign in to that account to repair or uninstall it, then reopen Setup.".into()),
            _ => Err(registration_error(1608)),
        },
        Err(error) => Err(registration_error(error)),
    }
}

fn version(value: &str) -> Option<(u32, u32, u32)> {
    let fields: Vec<_> = value.split('.').collect();
    if fields.len() != 3 {
        return None;
    }
    Some((
        fields[0].parse().ok()?,
        fields[1].parse().ok()?,
        fields[2].parse().ok()?,
    ))
}

pub fn action_allowed(package: &Package, installed: &[Installed], action: Action) -> bool {
    if installed.len() > 1 {
        return false;
    }
    let Some(current) = installed.first() else {
        return action == Action::Install;
    };
    match action {
        Action::Uninstall => true,
        Action::Repair | Action::Reinstall => {
            !current.advertised
                && current
                    .product_code
                    .eq_ignore_ascii_case(&package.product_code)
        }
        Action::Install => match (version(&package.version), version(&current.version)) {
            (Some(bundle), Some(existing)) => {
                bundle >= existing
                    && (current.advertised
                        || !current
                            .product_code
                            .eq_ignore_ascii_case(&package.product_code))
            }
            _ => false,
        },
    }
}

pub fn registration_matches(action: Action, target_code: &str, installed: &[Installed]) -> bool {
    let present = installed.iter().any(|p| {
        p.product_code.eq_ignore_ascii_case(target_code)
            && (action == Action::Uninstall || !p.advertised)
    });
    if action == Action::Uninstall {
        !present
    } else {
        present
    }
}

pub fn result_message(action: Action, code: i32) -> (bool, String) {
    let verb = match action {
        Action::Install => "Installation",
        Action::Repair => "Repair",
        Action::Reinstall => "Reinstallation",
        Action::Uninstall => "Uninstall",
    };
    match code {
        0 => (true, format!("{verb} complete.")),
        3010 | 1641 => (true, format!("{verb} complete. Restart Windows before using SwiftTunnel.")),
        1602 => (false, format!("{verb} was cancelled. No success was reported.")),
        1618 => (false, "Another installation is running. Wait for it to finish, then try again.".into()),
        1612 => (false, "Windows is missing this version's installer source. Use Repair with Setup for the installed version, or install a newer SwiftTunnel release, then retry.".into()),
        1638 => (false, "Another version is installed. Download Setup matching that version or a newer release.".into()),
        1633 => (false, "This package does not support this PC. Download the correct x64 or ARM64 setup.".into()),
        _ => (false, format!("{verb} could not complete (Windows Installer {code}). Restart Windows, close SwiftTunnel and retry. Contact support if it persists.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_products_do_not_hide_later_valid_installations() {
        let statuses = [1605, 1605, 0];
        let visible: Vec<_> = statuses
            .into_iter()
            .enumerate()
            .filter_map(|(index, status)| {
                match registration_version(
                    |_| {
                        if status == 0 {
                            Ok("3.1.6".into())
                        } else {
                            Err(status)
                        }
                    },
                    || panic!("only query state when VersionString is unavailable"),
                ) {
                    Ok(Some(_)) => Some(Ok(index)),
                    Ok(None) => None,
                    Err(error) => Some(Err(error)),
                }
            })
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(visible, vec![2]);
        for error in [5, 234, 1610] {
            let result = registration_version(|_| Err(error), || panic!("unexpected state lookup"));
            assert!(result.unwrap_err().contains(&error.to_string()));
        }
    }

    #[test]
    fn missing_version_string_uses_verified_registration_state_and_advertised_version() {
        for state in [1, 5] {
            let mut properties = vec![];
            let info = registration_version(
                |name| {
                    properties.push(name.to_string());
                    match name {
                        "VersionString" => Err(1608),
                        "Version" => Ok(((3u32 << 24) | (9 << 16) | 4).to_string()),
                        _ => panic!("unexpected property"),
                    }
                },
                || state,
            )
            .unwrap()
            .unwrap();
            assert_eq!(properties, ["VersionString", "Version"]);
            assert_eq!(info.version, "3.9.4");
            assert_eq!(info.advertised, state == 1);
        }
        let info = registration_version(
            |name| {
                if name == "Version" {
                    Ok(u32::MAX.to_string())
                } else {
                    Err(1608)
                }
            },
            || 1,
        )
        .unwrap()
        .unwrap();
        assert_eq!(info.version, "255.255.65535");
    }

    #[test]
    fn incomplete_registration_is_not_mistaken_for_absence_or_a_busy_installer() {
        for state in [2, 0, -2, -6] {
            let result = registration_version(|_| Err(1608), || state);
            let error = result.unwrap_err();
            assert!(!error.contains("Close other installers"));
        }
        for text in ["", "invalid", "3.9.4", "4294967296"] {
            let result = registration_version(
                |name| {
                    if name == "Version" {
                        Ok(text.into())
                    } else {
                        Err(1608)
                    }
                },
                || 1,
            );
            assert!(result.unwrap_err().contains("1608"));
        }
        assert!(registration_version(|_| Err(1608), || -1)
            .unwrap()
            .is_none());
        let mut count = 0;
        assert!(registration_version(
            |_| {
                count += 1;
                Err(if count == 1 { 1608 } else { 1605 })
            },
            || 1
        )
        .unwrap()
        .is_none());
        assert!(registration_version(|_| Err(1618), || panic!())
            .unwrap_err()
            .contains("Another installation"));
    }

    #[test]
    fn advertised_records_allow_install_but_not_repair_or_false_completion() {
        let package = package();
        let mut pending = installed("{A}", "3.1.6");
        pending[0].advertised = true;
        assert!(action_allowed(&package, &pending, Action::Install));
        assert!(action_allowed(&package, &pending, Action::Uninstall));
        assert!(!action_allowed(&package, &pending, Action::Repair));
        assert!(!action_allowed(&package, &pending, Action::Reinstall));
        assert!(!registration_matches(Action::Install, "{A}", &pending));
        assert!(!registration_matches(Action::Uninstall, "{A}", &pending));
        pending[0].version = "3.1.7".into();
        assert!(!action_allowed(&package, &pending, Action::Install));
    }
    fn package() -> Package {
        Package {
            name: "SwiftTunnel".into(),
            version: "3.1.6".into(),
            product_code: "{A}".into(),
            upgrade_code: "{F}".into(),
        }
    }
    fn installed(code: &str, version: &str) -> Vec<Installed> {
        vec![Installed {
            product_code: code.into(),
            version: version.into(),
            advertised: false,
        }]
    }
    #[test]
    fn new_install_does_not_offer_maintenance() {
        assert!(action_allowed(&package(), &[], Action::Install));
        for action in [Action::Repair, Action::Reinstall, Action::Uninstall] {
            assert!(!action_allowed(&package(), &[], action));
        }
    }
    #[test]
    fn rebuilt_same_version_package_can_replace_a_different_product() {
        assert!(action_allowed(
            &package(),
            &installed("{B}", "3.1.6"),
            Action::Install
        ));
        assert!(!action_allowed(
            &package(),
            &installed("{A}", "3.1.6"),
            Action::Install
        ));
        assert!(!action_allowed(
            &package(),
            &installed("{B}", "3.1.7"),
            Action::Install
        ));
    }
    #[test]
    fn maintenance_requires_the_exact_embedded_product() {
        assert!(action_allowed(
            &package(),
            &installed("{a}", "3.1.6"),
            Action::Repair
        ));
        assert!(action_allowed(
            &package(),
            &installed("{A}", "3.1.6"),
            Action::Reinstall
        ));
        assert!(!action_allowed(
            &package(),
            &installed("{B}", "3.1.5"),
            Action::Repair
        ));
        assert!(action_allowed(
            &package(),
            &installed("{B}", "3.1.5"),
            Action::Install
        ));
    }
    #[test]
    fn old_and_ambiguous_setups_cannot_downgrade_or_guess() {
        assert!(!action_allowed(
            &package(),
            &installed("{B}", "3.1.10"),
            Action::Install
        ));
        assert!(!action_allowed(
            &package(),
            &installed("{B}", "unknown"),
            Action::Install
        ));
        let mut two = installed("{A}", "3.1.6");
        two.extend(installed("{B}", "3.1.5"));
        for action in [
            Action::Install,
            Action::Repair,
            Action::Reinstall,
            Action::Uninstall,
        ] {
            assert!(!action_allowed(&package(), &two, action));
        }
    }
    #[test]
    fn uninstall_verifies_the_selected_older_product_not_the_bundle() {
        let old = installed("{B}", "3.1.5");
        assert!(!registration_matches(Action::Uninstall, "{b}", &old));
        assert!(registration_matches(Action::Uninstall, "{B}", &[]));
        assert!(!registration_matches(Action::Install, "{A}", &old));
        assert!(registration_matches(
            Action::Repair,
            "{a}",
            &installed("{A}", "3.1.6")
        ));
    }
    #[test]
    fn only_completed_msi_results_are_success() {
        for code in [0, 3010, 1641] {
            assert!(result_message(Action::Install, code).0);
        }
        for code in [1602, 1603, 1612, 1618, 1619, 1633, 1638] {
            assert!(!result_message(Action::Install, code).0);
        }
        assert!(result_message(Action::Repair, 3010)
            .1
            .contains("Restart Windows"));
    }
}
