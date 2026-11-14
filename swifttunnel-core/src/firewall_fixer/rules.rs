//! Native read-only rule discovery. Deletion retains its bounded, exact-name
//! and exact-direction command so it cannot broaden the old cleanup scope.
use super::{Result, RuleCleanup};
use windows::{
    Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, RPC_E_CHANGED_MODE},
        NetworkManagement::WindowsFirewall::{INetFwPolicy2, INetFwRules, NetFwPolicy2},
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
            CoUninitialize,
        },
    },
    core::{BSTR, HRESULT},
};

struct Apartment(bool);
impl Apartment {
    fn enter() -> windows::core::Result<Self> {
        let result = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if result == RPC_E_CHANGED_MODE {
            return Ok(Self(false));
        }
        result.ok()?;
        Ok(Self(true))
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        if self.0 {
            unsafe {
                CoUninitialize();
            }
        }
    }
}

pub(super) struct WindowsRules {
    // Release COM interfaces before uninitializing this apartment.
    rules: INetFwRules,
    _apartment: Apartment,
}
impl WindowsRules {
    pub(super) fn open() -> Result<Self> {
        let apartment = Apartment::enter()?;
        let policy: INetFwPolicy2 =
            unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }?;
        let rules = unsafe { policy.Rules() }?;
        Ok(Self {
            rules,
            _apartment: apartment,
        })
    }
}

fn presence_error(code: HRESULT) -> windows::core::Result<bool> {
    if code == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) {
        Ok(false)
    } else {
        Err(windows::core::Error::from_hresult(code))
    }
}

impl RuleCleanup for WindowsRules {
    fn present(&mut self, name: &str) -> Result<bool> {
        match unsafe { self.rules.Item(&BSTR::from(name)) } {
            Ok(_) => Ok(true),
            Err(error) => presence_error(error.code()).map_err(Into::into),
        }
    }
    fn remove(&mut self, name: &str, direction: &str) -> Result<()> {
        let output = crate::run_hidden_command_with_timeout(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={name}"),
                &format!("dir={direction}"),
            ],
            std::time::Duration::from_secs(15),
        );
        if !output.success {
            anyhow::bail!(
                "Windows did not remove the rule: {} {}",
                output.stdout.trim(),
                output.stderr.trim()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_documented_not_found_is_rule_absence() {
        assert!(!presence_error(HRESULT::from_win32(2)).unwrap());
        for code in [0x80070005u32, 0x80070057, 0x800706ba] {
            assert!(presence_error(HRESULT(code as i32)).is_err());
        }
    }
    #[test]
    fn native_lookup_guard_does_not_uninitialize_a_preexisting_sta_apartment() {
        use windows::Win32::System::Com::{
            APTTYPE, APTTYPE_MAINSTA, APTTYPE_STA, APTTYPEQUALIFIER, COINIT_APARTMENTTHREADED,
            CoGetApartmentType,
        };
        std::thread::spawn(|| unsafe {
            CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok().unwrap();
            let _owner = Apartment(true);
            {
                let borrowed = Apartment::enter().unwrap();
                assert!(!borrowed.0);
            }
            let mut kind = APTTYPE::default();
            let mut qualifier = APTTYPEQUALIFIER::default();
            CoGetApartmentType(&mut kind, &mut qualifier).unwrap();
            assert!(kind == APTTYPE_STA || kind == APTTYPE_MAINSTA);
        })
        .join()
        .unwrap();
    }
    #[test]
    #[ignore = "read-only query of this machine's Windows firewall rule store"]
    fn native_firewall_lookup_is_readonly_and_distinguishes_absence() {
        let mut rules = WindowsRules::open().unwrap();
        let name = format!("SwiftTunnel-Owned-ReadOnly-{:032x}", rand::random::<u128>());
        assert!(!rules.present(&name).unwrap());
        let mut present = 0;
        for (name, _) in crate::firewall_fixer::cleanup_targets() {
            present += usize::from(rules.present(&name).unwrap());
        }
        eprintln!(
            "Read-only native firewall lookup: random rule absent; {present} of 8 reserved names present. No rules changed."
        );
    }
}
