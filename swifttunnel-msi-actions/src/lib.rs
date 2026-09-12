//! Native MSI actions. No process launch, console, or work in DllMain.
//! The deferred action runs as SYSTEM, before any new files are installed.
//! Only missing cached packages of related per-machine Desktop products qualify.
//! Unknown state is retained for Windows Installer to handle normally.

mod registry;

// Keep synchronized with the explicit Desktop wix.upgradeCode. This is Tauri's
// original UUIDv5 for SwiftTunnel.exe.app.x64, also used on ARM64.
const UPGRADE_CODE: &str = "{E8A8D9AE-1DDB-53D0-BCF4-8268BDDC947D}";
const MAX_PRODUCTS: usize = 32;
type Result<T> = std::result::Result<T, String>;

fn canonical_guid(value: &str) -> Result<String> {
    if value.len() != 38
        || !value.bytes().enumerate().all(|(i, c)| match i {
            0 => c == b'{',
            37 => c == b'}',
            9 | 14 | 19 | 24 => c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
    {
        return Err("invalid product code".into());
    }
    Ok(value.to_ascii_uppercase())
}

fn product_list(value: &str) -> Result<Vec<String>> {
    if value.len() > MAX_PRODUCTS * 39 {
        return Err("too many related products".into());
    }
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    for code in value.split(';') {
        let code = canonical_guid(code)?;
        if result.contains(&code) {
            return Err("duplicate related product".into());
        }
        result.push(code);
    }
    if result.len() > MAX_PRODUCTS {
        return Err("too many related products".into());
    }
    Ok(result)
}

fn packed_guid(code: &str) -> String {
    // Callers supply a validated canonical GUID only.
    let digits: Vec<char> = code.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let mut result = String::with_capacity(32);
    for range in [0..8, 8..12, 12..16] {
        result.extend(digits[range].iter().rev());
    }
    for pair in digits[16..].chunks_exact(2) {
        result.push(pair[1]);
        result.push(pair[0]);
    }
    result
}

/// Only candidates recorded before repair may be removed from the upgrade list.
/// A missing machine key for a per-user product must never silently bypass removal.
fn remaining_products(
    related: &[String],
    candidates: &[String],
    mut confirmed_absent: impl FnMut(&str) -> bool,
) -> Vec<String> {
    related
        .iter()
        .filter(|code| !candidates.contains(code) || !confirmed_absent(code))
        .cloned()
        .collect()
}

#[link(name = "msi")]
extern "system" {
    fn MsiGetPropertyW(handle: u32, name: *const u16, value: *mut u16, size: *mut u32) -> u32;
    fn MsiSetPropertyW(handle: u32, name: *const u16, value: *const u16) -> u32;
    fn MsiCreateRecord(fields: u32) -> u32;
    fn MsiRecordSetStringW(record: u32, field: u32, value: *const u16) -> u32;
    fn MsiProcessMessage(handle: u32, kind: u32, record: u32) -> i32;
    fn MsiCloseHandle(handle: u32) -> u32;
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn property(handle: u32, name: &str) -> Result<String> {
    // All our inputs are bounded ASCII product lists, never arbitrary paths.
    let mut buffer = vec![0u16; MAX_PRODUCTS * 39 + 40];
    let mut size = buffer.len() as u32;
    let status =
        unsafe { MsiGetPropertyW(handle, wide(name).as_ptr(), buffer.as_mut_ptr(), &mut size) };
    if status != 0 {
        return Err(format!("reading {name} failed ({status})"));
    }
    String::from_utf16(&buffer[..size as usize]).map_err(|_| "invalid property encoding".into())
}

fn set_property(handle: u32, name: &str, value: &str) -> Result<()> {
    let status = unsafe { MsiSetPropertyW(handle, wide(name).as_ptr(), wide(value).as_ptr()) };
    if status != 0 {
        return Err(format!("setting {name} failed ({status})"));
    }
    Ok(())
}

fn log(handle: u32, message: &str) {
    unsafe {
        let record = MsiCreateRecord(0);
        if record != 0 {
            MsiRecordSetStringW(
                record,
                0,
                wide(&format!("SwiftTunnel recovery: {message}")).as_ptr(),
            );
            MsiProcessMessage(handle, 0x04000000, record); // INSTALLMESSAGE_INFO
            MsiCloseHandle(record);
        }
    }
}

fn entry(handle: u32, action: impl FnOnce() -> Result<()> + std::panic::UnwindSafe) -> u32 {
    match std::panic::catch_unwind(action) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            log(handle, &error);
            1603
        }
        Err(_) => {
            log(handle, "custom action panicked");
            1603
        }
    }
}

#[no_mangle]
pub extern "system" fn PrepareDesktopRecovery(handle: u32) -> u32 {
    entry(handle, || {
        let current = canonical_guid(&property(handle, "ProductCode")?)?;
        let related = product_list(&property(handle, "WIX_UPGRADE_DETECTED")?)?;
        let candidates: Vec<_> = related
            .into_iter()
            .filter(|code| {
                code != &current
                    && registry::is_desktop_machine_product(&windows_registry::LOCAL_MACHINE, code)
            })
            .collect();
        // Lowercase property names are private and cannot be supplied on msiexec's
        // command line. The deferred action independently rechecks identity/state.
        let codes = candidates.join(";");
        log(
            handle,
            &format!(
                "identified {} related Desktop machine registrations",
                candidates.len()
            ),
        );
        set_property(handle, "SwiftDesktopRecoveryCandidates", &codes)?;
        set_property(handle, "RepairDesktopOrphans", &codes)
    })
}

#[no_mangle]
pub extern "system" fn RepairDesktopOrphans(handle: u32) -> u32 {
    entry(handle, || {
        for code in product_list(&property(handle, "CustomActionData")?)? {
            if registry::repair_missing_package(&windows_registry::LOCAL_MACHINE, &code)? {
                log(
                    handle,
                    &format!("cleared missing-package Desktop registration {code}"),
                );
            } else {
                log(handle, &format!("left registration unchanged {code}"));
            }
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "system" fn RefreshDesktopUpgradeList(handle: u32) -> u32 {
    entry(handle, || {
        let related = product_list(&property(handle, "WIX_UPGRADE_DETECTED")?)?;
        let candidates = product_list(&property(handle, "SwiftDesktopRecoveryCandidates")?)?;
        let remaining = remaining_products(&related, &candidates, |code| {
            registry::registration_absent(&windows_registry::LOCAL_MACHINE, code)
        });
        set_property(handle, "WIX_UPGRADE_DETECTED", &remaining.join(";"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = "{F820821D-AF83-4972-B40A-4B4B4D53A92E}";
    const OTHER: &str = "{5EC81BE0-A95C-40A1-A761-C4846CED3900}";

    #[test]
    fn template_and_recovery_use_the_original_desktop_upgrade_family() {
        let config: serde_json::Value = serde_json::from_str(include_str!(
            "../../swifttunnel-desktop/src-tauri/tauri.conf.json"
        ))
        .unwrap();
        let code = config["bundle"]["windows"]["wix"]["upgradeCode"]
            .as_str()
            .unwrap();
        assert_eq!(
            canonical_guid(&format!("{{{code}}}")).unwrap(),
            UPGRADE_CODE
        );
    }

    #[test]
    fn product_codes_cannot_be_paths_or_unbounded_payloads() {
        for bad in [
            "..\\Products",
            "",
            "{Z820821D-AF83-4972-B40A-4B4B4D53A92E}",
            "F820821D-AF83-4972-B40A-4B4B4D53A92E",
        ] {
            assert!(canonical_guid(bad).is_err());
        }
        assert!(product_list(&format!("{OLD};{OLD}")).is_err());
        assert!(product_list(&format!("{OLD};")).is_err());
        assert!(product_list(&"x".repeat(2000)).is_err());
        assert_eq!(product_list(&OLD.to_lowercase()).unwrap(), [OLD]);
        assert!(product_list("").unwrap().is_empty());
    }

    #[test]
    fn guid_packing_matches_real_installer_registration() {
        assert_eq!(packed_guid(OLD), "D128028F38FA27944BA0B4B4D4359AE2");
    }

    #[test]
    fn absent_per_user_or_unrelated_products_are_not_skipped() {
        let related = vec![OLD.into(), OTHER.into()];
        assert_eq!(
            remaining_products(&related, &[OLD.into()], |_| true),
            [OTHER]
        );
    }

    #[test]
    fn healthy_or_unknown_registration_stays_in_upgrade_list() {
        let related = vec![OLD.into()];
        assert_eq!(remaining_products(&related, &related, |_| false), related);
    }
}
