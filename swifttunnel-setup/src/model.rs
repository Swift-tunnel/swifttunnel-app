//! Installer decisions kept independent of Windows and the elevated GUI.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Install,
    Repair,
    Reinstall,
    Uninstall,
}

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
        Action::Repair | Action::Reinstall => current
            .product_code
            .eq_ignore_ascii_case(&package.product_code),
        Action::Install => match (version(&package.version), version(&current.version)) {
            (Some(bundle), Some(existing)) => bundle > existing,
            _ => false,
        },
    }
}

pub fn registration_matches(action: Action, target_code: &str, installed: &[Installed]) -> bool {
    let present = installed
        .iter()
        .any(|p| p.product_code.eq_ignore_ascii_case(target_code));
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
