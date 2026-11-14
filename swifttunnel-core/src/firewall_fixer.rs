use crate::structs::*;
use log::{info, warn};
use std::path::PathBuf;

// UWP Roblox runs under Windows10Universal.exe, a generic Store host shared by
// unrelated Microsoft Store apps. Adding firewall rules keyed to that name
// would scope to Mail, Weather, etc. Per CLAUDE.md, UWP Roblox is intentionally
// not tunnel-eligible, so we omit it here.
const ROBLOX_EXECUTABLES: [&str; 3] = [
    "RobloxPlayerBeta.exe",
    "RobloxStudioBeta.exe",
    "RobloxCrashHandler.exe",
];

// Executable names written by earlier SwiftTunnel versions that we now reject.
// On upgrade these rules are still in the Windows firewall and would keep
// allowing the named (generic) host process through. The pre-apply cleanup
// pass explicitly deletes them so the over-scoping bug is closed for users
// migrating from older builds.
const LEGACY_FIREWALL_EXECUTABLES: &[&str] = &["Windows10Universal.exe"];

const FIREWALL_RULE_PREFIX: &str = "SwiftTunnel - Roblox";

#[cfg(windows)]
mod rules;

fn cleanup_targets() -> Vec<(String, &'static str)> {
    ROBLOX_EXECUTABLES
        .iter()
        .copied()
        .chain(LEGACY_FIREWALL_EXECUTABLES.iter().copied())
        .flat_map(|exe| {
            [("Out", "out"), ("In", "in")]
                .into_iter()
                .map(move |(suffix, direction)| {
                    (format!("{FIREWALL_RULE_PREFIX} {exe} {suffix}"), direction)
                })
        })
        .collect()
}

trait RuleCleanup {
    fn present(&mut self, name: &str) -> Result<bool>;
    fn remove(&mut self, name: &str, direction: &str) -> Result<()>;
}

fn cleanup_with_rules(rules: &mut impl RuleCleanup) -> Result<()> {
    cleanup_named_rules(rules, &cleanup_targets())
}

fn cleanup_named_rules(rules: &mut impl RuleCleanup, targets: &[(String, &str)]) -> Result<()> {
    // Complete discovery before making changes. Access/provider failures must
    // not look like absence, or become a successful cleanup result.
    let present = targets
        .iter()
        .map(|(name, _)| rules.present(name))
        .collect::<Result<Vec<_>>>()?;
    let mut errors = Vec::new();
    let mut attempted = false;
    for ((name, direction), present) in targets.iter().zip(present) {
        if present {
            attempted = true;
            if let Err(error) = rules.remove(name, direction) {
                errors.push(format!("{name}: {error}"));
            }
        }
    }
    if !attempted {
        return Ok(());
    }
    // A reported deletion success is not enough. Check every reserved name
    // again, including duplicates or a policy that Windows would not remove.
    let mut verified = true;
    for (name, _) in targets {
        match rules.present(name) {
            Ok(false) => {}
            Ok(true) => {
                verified = false;
                errors.push(format!("{name}: a rule remains after cleanup"));
            }
            Err(error) => {
                verified = false;
                errors.push(format!("{name}: removal could not be verified: {error}"));
            }
        }
    }
    if verified {
        for error in errors {
            warn!("Firewall deletion reported a failure, but rule absence was verified: {error}");
        }
        Ok(())
    } else {
        anyhow::bail!(
            "SwiftTunnel firewall cleanup did not finish: {}",
            errors.join("; ")
        )
    }
}

/// The legacy IPv6 block belongs to SwiftTunnel. Query its reserved name
/// natively before and after bounded deletion; localized tool errors cannot
/// prove absence. Keep deletion scoped to the original outbound direction.
pub(crate) fn remove_legacy_ipv6_block_rule() -> Result<()> {
    #[cfg(windows)]
    {
        cleanup_named_rules(
            &mut rules::WindowsRules::open()?,
            &[(
                crate::vpn::ipv6_recovery::IPV6_BLOCK_RULE_NAME.into(),
                "out",
            )],
        )
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("Windows firewall cleanup is unavailable on this platform")
    }
}

pub struct FirewallFixer {
    rules_applied: bool,
}

impl FirewallFixer {
    pub fn new() -> Self {
        Self {
            rules_applied: false,
        }
    }

    fn remove_swifttunnel_rules_by_prefix() -> Result<()> {
        #[cfg(windows)]
        {
            cleanup_with_rules(&mut rules::WindowsRules::open()?)
        }
        #[cfg(not(windows))]
        {
            anyhow::bail!("Windows firewall cleanup is unavailable on this platform")
        }
    }

    /// Add Roblox firewall allow rules and refresh the DNS/ARP caches.
    pub fn apply(&mut self) -> Result<()> {
        if self.rules_applied {
            info!("Firewall fix already applied, skipping");
            return Ok(());
        }
        let rules_added = apply_rules_with(
            &find_roblox_executables(),
            Self::remove_swifttunnel_rules_by_prefix,
            add_rule,
            refresh_network_caches,
        )?;
        self.rules_applied = true;
        info!("Roblox firewall fix applied successfully ({rules_added} rule(s))");
        Ok(())
    }

    /// Restore: remove all SwiftTunnel Roblox firewall rules.
    pub fn restore(&mut self) -> Result<()> {
        if !self.rules_applied {
            info!("Firewall fixer had no in-memory state; removing any stale SwiftTunnel rules");
        }

        info!("Removing SwiftTunnel Roblox firewall rules");

        // Rule names are shared across install paths and versions. The exact
        // known-name pass also handles removed installs and legacy rules.
        Self::remove_swifttunnel_rules_by_prefix()?;

        self.rules_applied = false;
        info!("SwiftTunnel Roblox firewall rules removed");
        Ok(())
    }
}

fn apply_rules_with(
    executables: &[(String, PathBuf)],
    mut cleanup: impl FnMut() -> Result<()>,
    mut add: impl FnMut(&str, &std::path::Path, &str) -> Result<()>,
    refresh: impl FnOnce(),
) -> Result<usize> {
    if executables.is_empty() {
        anyhow::bail!("Roblox firewall fix could not add rules: no Roblox executables found");
    }
    cleanup()?;
    let mut added = 0;
    let mut failed = 0;
    for (exe, path) in executables {
        for (suffix, direction) in [("Out", "out"), ("In", "in")] {
            let name = format!("{FIREWALL_RULE_PREFIX} {exe} {suffix}");
            match add(&name, path, direction) {
                Ok(()) => added += 1,
                Err(error) => {
                    failed += 1;
                    warn!("Failed to add {direction} firewall rule for {exe}: {error}");
                }
            }
        }
    }
    if failed > 0 {
        if let Err(error) = cleanup() {
            anyhow::bail!(
                "Roblox firewall rules could not all be added, and rollback also failed: {error}"
            );
        }
        anyhow::bail!("Roblox firewall fix failed to add {failed} firewall rule(s)");
    }
    // Cache refreshes affect the whole PC. They belong only after the
    // requested allow rules have actually been created successfully.
    refresh();
    Ok(added)
}

fn add_rule(name: &str, path: &std::path::Path, direction: &str) -> Result<()> {
    let output = crate::run_hidden_command_with_timeout(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={name}"),
            &format!("dir={direction}"),
            "action=allow",
            &format!("program={}", path.to_string_lossy()),
            "enable=yes",
        ],
        std::time::Duration::from_secs(15),
    );
    if !output.success {
        anyhow::bail!(
            "Windows did not add the rule: {} {}",
            output.stdout.trim(),
            output.stderr.trim()
        );
    }
    Ok(())
}

fn refresh_network_caches() {
    // 2. Flush DNS cache
    // A wedged DNS Client service hangs flushdns, and this runs inside
    // Repair, so an unbounded call here is one of the ways Repair can spin
    // forever without reporting anything.
    let output = crate::run_hidden_command_with_timeout(
        "ipconfig",
        &["/flushdns"],
        std::time::Duration::from_secs(30),
    );
    if output.success {
        info!("DNS cache flushed");
    } else {
        warn!("Failed to flush DNS cache: {}", output.stderr.trim());
    }

    // 3. Flush ARP cache
    let output = crate::run_hidden_command_with_timeout(
        "netsh",
        &["interface", "ip", "delete", "arpcache"],
        std::time::Duration::from_secs(30),
    );
    if output.success {
        info!("ARP cache flushed");
    } else {
        warn!("Failed to flush ARP cache: {}", output.stderr.trim());
    }
}

impl Default for FirewallFixer {
    fn default() -> Self {
        Self::new()
    }
}

/// Scan the global and VNG clients for known Roblox executables.
///
/// Returns `Vec<(exe_name, full_path)>` for each executable found.
fn find_roblox_executables() -> Vec<(String, PathBuf)> {
    match std::env::var_os("LOCALAPPDATA") {
        Some(root) => find_roblox_executables_in(&PathBuf::from(root)),
        None => Vec::new(),
    }
}

fn find_roblox_executables_in(local: &std::path::Path) -> Vec<(String, PathBuf)> {
    let mut found = Vec::new();
    for client in ["Roblox", "RobloxPCVNG"] {
        let versions = local.join(client).join("Versions");
        let Ok(entries) = std::fs::read_dir(&versions) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            for name in ROBLOX_EXECUTABLES {
                let executable = path.join(name);
                if executable.is_file() {
                    found.push((name.into(), executable));
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FixtureRules {
        present: std::collections::HashSet<String>,
        removed: Vec<(String, String)>,
        fail_remove: Option<String>,
        keep_remove: bool,
        error_after_removing: bool,
        fail_query: Option<usize>,
        queries: usize,
    }
    impl RuleCleanup for FixtureRules {
        fn present(&mut self, name: &str) -> Result<bool> {
            self.queries += 1;
            if self.fail_query == Some(self.queries) {
                anyhow::bail!("owned query failure");
            }
            Ok(self.present.contains(name))
        }
        fn remove(&mut self, name: &str, direction: &str) -> Result<()> {
            self.removed.push((name.into(), direction.into()));
            if self.fail_remove.as_deref() == Some(name) {
                anyhow::bail!("owned removal failure");
            }
            if !self.keep_remove {
                self.present.remove(name);
            }
            if self.error_after_removing {
                anyhow::bail!("owned command failed after removal");
            }
            Ok(())
        }
    }

    #[test]
    fn legacy_ipv6_cleanup_requires_verified_absence_and_keeps_its_exact_scope() {
        let name = crate::vpn::ipv6_recovery::IPV6_BLOCK_RULE_NAME.to_string();
        let unrelated = format!("{name}-Other");
        let target = [(name.clone(), "out")];
        let mut rules = FixtureRules {
            present: [name.clone(), unrelated.clone()].into(),
            ..Default::default()
        };
        cleanup_named_rules(&mut rules, &target).unwrap();
        assert_eq!(rules.removed, [(name.clone(), "out".into())]);
        assert!(rules.present.contains(&unrelated));
        let mut unverified = FixtureRules {
            present: [name.clone()].into(),
            fail_query: Some(2), // Deletion succeeds, but the read-back fails.
            ..Default::default()
        };
        assert!(cleanup_named_rules(&mut unverified, &target).is_err());
        let mut absent = FixtureRules::default();
        cleanup_named_rules(&mut absent, &target).unwrap();
        assert!(absent.removed.is_empty());
        let mut unknown = FixtureRules {
            fail_query: Some(1),
            ..Default::default()
        };
        assert!(cleanup_named_rules(&mut unknown, &target).is_err());
        assert!(unknown.removed.is_empty());
    }

    #[test]
    fn missing_installation_and_failed_rule_creation_do_not_refresh_network_caches() {
        let missing = apply_rules_with(
            &[],
            || panic!("must not clean rules"),
            |_, _, _| panic!("must not add rules"),
            || panic!("must not refresh caches"),
        );
        assert!(missing.is_err());
        let executables = vec![(
            "RobloxPlayerBeta.exe".into(),
            PathBuf::from("owned-player.exe"),
        )];
        let trace = std::cell::RefCell::new(Vec::new());
        let result = apply_rules_with(
            &executables,
            || {
                trace.borrow_mut().push("cleanup");
                Ok(())
            },
            |_, _, direction| {
                trace.borrow_mut().push(if direction == "out" {
                    "add-out"
                } else {
                    "add-in"
                });
                anyhow::bail!("owned add failure")
            },
            || panic!("failed rules must not refresh DNS or ARP"),
        );
        assert!(result.is_err());
        assert_eq!(*trace.borrow(), ["cleanup", "add-out", "add-in", "cleanup"]);
    }

    #[test]
    fn successful_rule_creation_refreshes_only_after_both_scoped_rules_exist() {
        let executables = vec![(
            "RobloxPlayerBeta.exe".into(),
            PathBuf::from("owned-vng-player.exe"),
        )];
        let trace = std::cell::RefCell::new(Vec::new());
        let result = apply_rules_with(
            &executables,
            || {
                trace.borrow_mut().push("cleanup");
                Ok(())
            },
            |name, path, direction| {
                assert_eq!(path, executables[0].1);
                assert_eq!(
                    name,
                    format!(
                        "{FIREWALL_RULE_PREFIX} RobloxPlayerBeta.exe {}",
                        if direction == "out" { "Out" } else { "In" }
                    )
                );
                trace.borrow_mut().push(if direction == "out" {
                    "add-out"
                } else {
                    "add-in"
                });
                Ok(())
            },
            || trace.borrow_mut().push("refresh"),
        )
        .unwrap();
        assert_eq!(result, 2);
        assert_eq!(*trace.borrow(), ["cleanup", "add-out", "add-in", "refresh"]);
    }

    #[test]
    fn verified_empty_firewall_cleanup_starts_no_deletion_and_preserves_unrelated_names() {
        let unrelated = "SwiftTunnel - Roblox OtherApp Out".to_string();
        let mut rules = FixtureRules {
            present: [unrelated.clone()].into(),
            ..Default::default()
        };
        cleanup_with_rules(&mut rules).unwrap();
        assert!(rules.removed.is_empty());
        assert!(rules.present.contains(&unrelated));
        assert_eq!(rules.queries, 8);
    }

    #[test]
    fn cleanup_verifies_actual_removal_and_attempts_independent_rules() {
        let names = cleanup_targets();
        let mut rules = FixtureRules {
            present: [names[0].0.clone(), names[1].0.clone()].into(),
            fail_remove: Some(names[0].0.clone()),
            ..Default::default()
        };
        let error = cleanup_with_rules(&mut rules).unwrap_err().to_string();
        assert_eq!(
            rules.removed,
            vec![
                (names[0].0.clone(), "out".into()),
                (names[1].0.clone(), "in".into())
            ]
        );
        assert!(rules.present.contains(&names[0].0));
        assert!(!rules.present.contains(&names[1].0));
        assert!(error.contains("remains") && error.contains("owned removal failure"));
        let mut false_success = FixtureRules {
            present: [names[0].0.clone()].into(),
            keep_remove: true,
            ..Default::default()
        };
        assert!(cleanup_with_rules(&mut false_success).is_err());
        let mut converged = FixtureRules {
            present: [names[0].0.clone()].into(),
            error_after_removing: true,
            ..Default::default()
        };
        assert!(cleanup_with_rules(&mut converged).is_ok());
    }

    #[test]
    fn failed_rule_queries_never_authorize_changes_or_claim_verified_cleanup() {
        let name = cleanup_targets()[0].0.clone();
        let mut before = FixtureRules {
            present: [name.clone()].into(),
            fail_query: Some(3),
            ..Default::default()
        };
        assert!(cleanup_with_rules(&mut before).is_err());
        assert!(before.removed.is_empty());
        let mut after = FixtureRules {
            present: [name].into(),
            fail_query: Some(9),
            ..Default::default()
        };
        assert!(cleanup_with_rules(&mut after).is_err());
        assert_eq!(after.removed.len(), 1);
        assert_eq!(after.queries, 16);
    }

    #[test]
    fn discovery_supports_vng_alone_and_both_clients_without_store_hosts() {
        let root = std::env::temp_dir().join(format!(
            "swift-firewall-audit-{:032x}",
            rand::random::<u128>()
        ));
        let vng = root
            .join("RobloxPCVNG")
            .join("Versions")
            .join("version-test");
        std::fs::create_dir_all(&vng).unwrap();
        std::fs::write(vng.join("RobloxPlayerBeta.exe"), "fixture").unwrap();
        std::fs::write(vng.join("Windows10Universal.exe"), "fixture").unwrap();
        assert_eq!(find_roblox_executables_in(&root).len(), 1);
        let main = root.join("Roblox").join("Versions").join("version-test");
        std::fs::create_dir_all(&main).unwrap();
        std::fs::write(main.join("RobloxPlayerBeta.exe"), "fixture").unwrap();
        assert_eq!(find_roblox_executables_in(&root).len(), 2);
        assert!(root.starts_with(std::env::temp_dir()));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn firewall_fixer_default_not_applied() {
        let fixer = FirewallFixer::new();
        assert!(!fixer.rules_applied);
    }

    #[test]
    fn find_roblox_executables_does_not_panic() {
        // Should not panic even if Roblox is not installed
        let exes = find_roblox_executables();
        // On non-Windows or without Roblox, this will be empty
        assert!(
            exes.iter()
                .all(|(name, path)| ROBLOX_EXECUTABLES.contains(&name.as_str()) && path.is_file())
        );
    }

    #[test]
    #[ignore = "Mutates Windows firewall rules; requires an isolated testbench"]
    fn restore_removes_real_rules_on_an_isolated_machine() {
        let mut fixer = FirewallFixer::new();
        let result = fixer.restore();
        assert!(result.is_ok());
    }

    /// Negative test (per global CLAUDE.md failure-mode rules): the generic
    /// UWP Store host `Windows10Universal.exe` must not be in our firewall
    /// rule list. It is shared across unrelated Microsoft Store apps and
    /// CLAUDE.md explicitly marks UWP Roblox as not tunnel-eligible.
    #[test]
    fn windows10universal_is_not_a_roblox_executable_target() {
        assert!(
            !ROBLOX_EXECUTABLES.contains(&"Windows10Universal.exe"),
            "Windows10Universal.exe is a generic Store host shared with other Store apps; \
             firewall rules keyed to it would scope to Mail, Weather, etc."
        );
    }

    #[test]
    fn roblox_executables_list_only_targets_real_player_binaries() {
        for exe in &ROBLOX_EXECUTABLES {
            assert!(
                exe.starts_with("Roblox"),
                "unexpected firewall target {exe}: must be a Roblox-prefixed exe"
            );
        }
    }

    #[test]
    fn rule_name_prefix_is_stable() {
        // Restore depends on this prefix matching what we wrote previously.
        // Changing the prefix would orphan rules from older app versions.
        assert_eq!(FIREWALL_RULE_PREFIX, "SwiftTunnel - Roblox");
    }

    #[test]
    fn legacy_firewall_executables_targets_windows10universal() {
        // Older SwiftTunnel builds wrote firewall rules for
        // Windows10Universal.exe. Removing it from ROBLOX_EXECUTABLES is not
        // enough — the rules on the user's box must also be deleted on
        // upgrade. This test pins the cleanup list so a regression
        // (dropping the entry, renaming the constant) breaks the build.
        assert!(
            LEGACY_FIREWALL_EXECUTABLES.contains(&"Windows10Universal.exe"),
            "legacy firewall cleanup must keep Windows10Universal.exe so upgrade installs strip it"
        );
    }
}
