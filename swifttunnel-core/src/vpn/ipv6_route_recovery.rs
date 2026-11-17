//! Temporary IPv6 default-route steering with durable per-interface recovery.
//! Keep routes and router discovery intact. Windows' IgnoreDefaultRoutes flag
//! provides IPv4 fallback without deleting a player's active/static routes.
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::{fs, path::PathBuf};
use windows::Win32::{
    Foundation::WIN32_ERROR,
    NetworkManagement::{
        IpHelper::{
            ConvertInterfaceGuidToLuid, ConvertInterfaceLuidToGuid, FreeMibTable,
            GetIpForwardTable2, GetIpInterfaceEntry, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
            SetIpInterfaceEntry,
        },
        Ndis::NET_LUID_LH,
    },
    Networking::WinSock::{AF_INET6, NL_ROUTE_ORIGIN, NlroRouterAdvertisement},
};
use windows::core::GUID;

static GATE: Mutex<()> = Mutex::new(());
const MAX_RECORDS: usize = 64;
const MAX_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Original {
    interface_guid: String,
    original_ignore_default_routes: bool,
}

impl Original {
    fn validate(&self) -> Result<(), String> {
        let guid = GUID::try_from(self.interface_guid.as_str())
            .map_err(|_| "Invalid IPv6 route recovery interface")?;
        // This version only changes false -> true. Do not accept an original
        // that could cause recovery to disable someone's default routes.
        if guid == GUID::zeroed()
            || format!("{guid:?}") != self.interface_guid
            || self.original_ignore_default_routes
        {
            return Err("Invalid IPv6 route recovery record".into());
        }
        Ok(())
    }
}

trait JournalStorage {
    fn read_text(&self) -> Result<Option<String>, String>;
    fn write_bytes(&self, bytes: &[u8]) -> Result<(), String>;
}

#[cfg(not(test))]
fn journal_store() -> Result<swifttunnel_installer_cache::ProtectedRecoveryStore, String> {
    swifttunnel_installer_cache::ProtectedRecoveryStore::open()
        .map_err(|error| format!("Could not open protected IPv6 route recovery storage: {error}"))
}

#[cfg(not(test))]
impl JournalStorage for swifttunnel_installer_cache::ProtectedRecoveryStore {
    fn read_text(&self) -> Result<Option<String>, String> {
        match self.read_ipv6_routes() {
            Ok(text) => Ok(Some(text)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("Could not read IPv6 route recovery data: {error}")),
        }
    }

    fn write_bytes(&self, bytes: &[u8]) -> Result<(), String> {
        self.write_ipv6_routes(bytes)
            .map_err(|error| format!("Could not save IPv6 route recovery data: {error}"))
    }
}

#[cfg(test)]
fn journal_store() -> Result<PathBuf, String> {
    Ok(crate::test_support::recovery_directory().join("ipv6_route_recovery.json"))
}

#[cfg(test)]
impl JournalStorage for PathBuf {
    fn read_text(&self) -> Result<Option<String>, String> {
        crate::roblox_native_launch::safe_path(self)?;
        match crate::utils::read_text_file_bounded(self, MAX_BYTES, "IPv6 route recovery") {
            Ok(text) => Ok(Some(text)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("Could not read IPv6 route recovery data: {error}")),
        }
    }

    fn write_bytes(&self, bytes: &[u8]) -> Result<(), String> {
        crate::roblox_native_launch::safe_path(self)?;
        if bytes == b"[]" {
            return match fs::remove_file(self) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.to_string()),
            };
        }
        fs::create_dir_all(self.parent().ok_or("Invalid recovery directory")?)
            .map_err(|error| error.to_string())?;
        crate::roblox_native_launch::safe_path(self)?;
        crate::atomic_file::replace(self, bytes).map_err(|error| error.to_string())
    }
}

fn read(store: &dyn JournalStorage) -> Result<Vec<Original>, String> {
    let Some(text) = store.read_text()? else {
        return Ok(Vec::new());
    };
    if text.len() > MAX_BYTES {
        return Err("IPv6 route recovery data is too large".into());
    }
    let records: Vec<Original> = serde_json::from_str(&text)
        .map_err(|_| "IPv6 route recovery data could not be read; original file kept")?;
    if records.len() > MAX_RECORDS {
        return Err("IPv6 route recovery data has too many interfaces".into());
    }
    for (index, record) in records.iter().enumerate() {
        record.validate()?;
        if records[..index]
            .iter()
            .any(|old| old.interface_guid == record.interface_guid)
        {
            return Err("IPv6 route recovery data has duplicate interfaces".into());
        }
    }
    Ok(records)
}

fn write(store: &dyn JournalStorage, records: &[Original]) -> Result<(), String> {
    let bytes = serde_json::to_vec(records).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_BYTES || records.len() > MAX_RECORDS {
        return Err("IPv6 route recovery data is too large".into());
    }
    // Production publishes even the empty journal with administrator ownership
    // and a protected DACL. It never uses the caller's default file permissions.
    store.write_bytes(&bytes)
}

fn record_before_change(
    store: &dyn JournalStorage,
    original: Original,
    change: impl FnOnce() -> Result<bool, String>,
) -> Result<bool, String> {
    original.validate()?;
    let mut records = read(store)?;
    if records
        .iter()
        .any(|entry| entry.interface_guid == original.interface_guid)
    {
        return Err("This interface still has pending IPv6 route recovery".into());
    }
    records.push(original);
    write(store, &records)?;
    // Keep the original on every failure: a native setter can fail after the
    // change took effect. Restoration checks the current setting before writing.
    let changed = change()?;
    if !changed {
        // The setter was never called (for example a manual route appeared).
        // Do not claim ownership of another application's new policy.
        records.pop();
        write(store, &records)?;
    }
    Ok(changed)
}

fn recover_at(
    store: &dyn JournalStorage,
    mut restore: impl FnMut(&Original) -> Result<(), String>,
) -> Result<bool, String> {
    let records = read(store)?;
    if records.is_empty() {
        return Ok(false);
    }
    let mut pending = Vec::new();
    let mut first_error = None;
    for original in records {
        if let Err(error) = restore(&original) {
            log::warn!(
                "IPv6 default-route recovery pending on interface {}: {error}",
                original.interface_guid
            );
            first_error.get_or_insert(error);
            pending.push(original);
        }
    }
    // One unavailable/unplugged interface must not hide successful recovery
    // of another, or lose its own original during a later adapter switch.
    if let Err(write_error) = write(store, &pending) {
        return Err(match first_error {
            Some(restore_error) => {
                format!("{restore_error}; could not save recovery progress: {write_error}")
            }
            None => write_error,
        });
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(true)
}

fn status(result: WIN32_ERROR, operation: &str) -> Result<(), String> {
    if result.0 == 0 {
        Ok(())
    } else {
        Err(format!("{operation} failed (Windows {})", result.0))
    }
}

fn interface_for_guid(guid: &GUID) -> Result<MIB_IPINTERFACE_ROW, String> {
    let mut luid = NET_LUID_LH::default();
    status(
        unsafe { ConvertInterfaceGuidToLuid(guid, &mut luid) },
        "Find IPv6 interface",
    )?;
    let mut row = MIB_IPINTERFACE_ROW {
        Family: AF_INET6,
        InterfaceLuid: luid,
        ..Default::default()
    };
    status(
        unsafe { GetIpInterfaceEntry(&mut row) },
        "Read IPv6 interface",
    )?;
    Ok(row)
}

fn may_steer(ignore_defaults: bool, default_origins: &[NL_ROUTE_ORIGIN]) -> bool {
    !ignore_defaults
        && !default_origins.is_empty()
        && default_origins
            .iter()
            .all(|origin| *origin == NlroRouterAdvertisement)
}

fn default_origins(row: &MIB_IPINTERFACE_ROW) -> Result<Vec<NL_ROUTE_ORIGIN>, String> {
    struct Table(*mut MIB_IPFORWARD_TABLE2);
    impl Drop for Table {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { FreeMibTable(self.0.cast()) }
            }
        }
    }
    let mut pointer = std::ptr::null_mut();
    let result = unsafe { GetIpForwardTable2(AF_INET6, &mut pointer) };
    let table = Table(pointer);
    status(result, "Read IPv6 default routes")?;
    if table.0.is_null() {
        return Err("Windows returned no IPv6 route table".into());
    }
    let count = unsafe { (*table.0).NumEntries } as usize;
    if count > 65536 {
        return Err("IPv6 route table is too large to verify".into());
    }
    let rows = unsafe {
        std::ptr::addr_of!((*table.0).Table)
            .cast::<windows::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2>()
    };
    let mut origins = Vec::new();
    for index in 0..count {
        // The OS owns this complete, aligned native allocation until FreeMibTable.
        let route = unsafe { &*rows.add(index) };
        if unsafe { route.InterfaceLuid.Value == row.InterfaceLuid.Value }
            && route.DestinationPrefix.PrefixLength == 0
        {
            origins.push(route.Origin);
        }
    }
    Ok(origins)
}

fn restore_native(original: &Original) -> Result<(), String> {
    original.validate()?;
    let guid =
        GUID::try_from(original.interface_guid.as_str()).map_err(|error| error.to_string())?;
    let row = interface_for_guid(&guid)?;
    restore_with(
        original,
        row,
        |row| {
            status(
                unsafe { SetIpInterfaceEntry(row) },
                "Restore IPv6 default-route policy",
            )
        },
        || interface_for_guid(&guid).map(|row| row.DisableDefaultRoutes),
    )
}

fn restore_with(
    original: &Original,
    mut row: MIB_IPINTERFACE_ROW,
    set: impl FnOnce(&mut MIB_IPINTERFACE_ROW) -> Result<(), String>,
    read_back: impl FnOnce() -> Result<bool, String>,
) -> Result<(), String> {
    original.validate()?;
    if !row.DisableDefaultRoutes {
        return Ok(()); // Already restored, including after a reboot.
    }
    // Only the one field we changed. In particular, never turn on router
    // discovery or reconstruct/delete routes based on a saved friendly name.
    row.DisableDefaultRoutes = original.original_ignore_default_routes;
    set(&mut row)?;
    if read_back()? != original.original_ignore_default_routes {
        return Err("Windows did not confirm restoring IPv6 default-route policy".into());
    }
    Ok(())
}

pub(super) fn recover() -> Result<bool, String> {
    let _guard = GATE.lock();
    let store = journal_store()?;
    recover_at(&store, restore_native)
}

pub(super) fn steer(if_index: u32) -> Result<bool, String> {
    let _guard = GATE.lock();
    let store = journal_store()?;
    // Retry originals, but an unplugged old interface must not prevent a new
    // interface from working. Its record remains in the journal.
    if let Err(error) = recover_at(&store, restore_native) {
        log::warn!("Some IPv6 route recovery remains pending: {error}");
    }
    let mut row = MIB_IPINTERFACE_ROW {
        Family: AF_INET6,
        InterfaceIndex: if_index,
        ..Default::default()
    };
    status(
        unsafe { GetIpInterfaceEntry(&mut row) },
        "Read IPv6 route policy",
    )?;
    if !may_steer(row.DisableDefaultRoutes, &default_origins(&row)?) {
        return Ok(false);
    }
    let mut guid = GUID::zeroed();
    status(
        unsafe { ConvertInterfaceLuidToGuid(&row.InterfaceLuid, &mut guid) },
        "Identify IPv6 interface",
    )?;
    record_before_change(
        &store,
        Original {
            interface_guid: format!("{guid:?}"),
            original_ignore_default_routes: row.DisableDefaultRoutes,
        },
        || {
            // Refresh the full row so unrelated IP-interface preferences are not
            // replaced with the earlier read. Custom/default-route changes skip
            // steering without claiming another writer's new policy.
            let mut current = interface_for_guid(&guid)?;
            if !may_steer(current.DisableDefaultRoutes, &default_origins(&current)?) {
                return Ok(false);
            }
            current.DisableDefaultRoutes = true;
            status(
                unsafe { SetIpInterfaceEntry(&mut current) },
                "Steer IPv6 default routes",
            )?;
            if !interface_for_guid(&guid)?.DisableDefaultRoutes {
                return Err("Windows did not confirm IPv6 default-route steering".into());
            }
            Ok(true)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Networking::WinSock::NlroManual;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("swift-ipv6-routes-{:032x}", rand::random::<u128>()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> PathBuf {
            self.0.join("originals.json")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn original(id: u128) -> Original {
        Original {
            interface_guid: format!("{:?}", GUID::from_u128(id)),
            original_ignore_default_routes: false,
        }
    }

    #[test]
    fn custom_and_absent_default_routes_are_left_unchanged() {
        assert!(may_steer(false, &[NlroRouterAdvertisement]));
        assert!(!may_steer(true, &[NlroRouterAdvertisement]));
        assert!(!may_steer(false, &[]));
        assert!(!may_steer(false, &[NlroManual]));
        assert!(!may_steer(false, &[NlroRouterAdvertisement, NlroManual]));
        assert!(!may_steer(false, &[NL_ROUTE_ORIGIN(999)]));
    }

    #[test]
    fn restoration_preserves_discovery_and_other_live_interface_preferences() {
        use windows::Win32::Networking::WinSock::RouterDiscoveryDhcp;
        let row = MIB_IPINTERFACE_ROW {
            Family: AF_INET6,
            InterfaceIndex: 55,
            RouterDiscoveryBehavior: RouterDiscoveryDhcp,
            Metric: 77,
            DisableDefaultRoutes: true,
            ..Default::default()
        };
        restore_with(
            &original(1),
            row,
            |updated| {
                assert!(!updated.DisableDefaultRoutes);
                assert_eq!(updated.RouterDiscoveryBehavior, RouterDiscoveryDhcp);
                assert_eq!(updated.Metric, 77);
                assert_eq!(updated.InterfaceIndex, 55);
                Ok(())
            },
            || Ok(false),
        )
        .unwrap();
        assert!(restore_with(&original(1), row, |_| Ok(()), || Ok(true)).is_err());
        let already_restored = MIB_IPINTERFACE_ROW {
            DisableDefaultRoutes: false,
            ..row
        };
        restore_with(
            &original(1),
            already_restored,
            |_| panic!("already restored policy must stay untouched"),
            || panic!("no write to verify"),
        )
        .unwrap();
    }

    #[test]
    fn original_is_durable_before_native_change_and_kept_after_failure() {
        let dir = Fixture::new();
        let path = dir.path();
        let saved = original(1);
        assert!(
            record_before_change(&path, saved.clone(), || {
                assert_eq!(read(&path).unwrap(), vec![saved.clone()]);
                Err("synthetic setter failure".into())
            })
            .is_err()
        );
        assert_eq!(read(&path).unwrap(), vec![saved.clone()]);
        assert!(
            record_before_change(&path, saved, || panic!(
                "pending original must not be replaced"
            ))
            .is_err()
        );
        recover_at(&path, |_| Ok(())).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn failed_recording_never_changes_an_interface() {
        let dir = Fixture::new();
        let path = dir.path();
        fs::write(&path, "damaged original").unwrap();
        assert!(
            record_before_change(&path, original(1), || panic!("must not change IPv6")).is_err()
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "damaged original");
    }

    #[test]
    fn protected_storage_failures_never_allow_an_unrecorded_change() {
        struct RefusingStore;
        impl JournalStorage for RefusingStore {
            fn read_text(&self) -> Result<Option<String>, String> {
                Ok(None)
            }
            fn write_bytes(&self, _: &[u8]) -> Result<(), String> {
                Err("protected publication refused".into())
            }
        }
        let error = record_before_change(&RefusingStore, original(1), || {
            panic!("must not mutate without a protected original")
        })
        .unwrap_err();
        assert!(error.contains("protected publication refused"));
    }

    #[test]
    fn an_empty_protected_journal_does_not_need_another_write_or_restore() {
        struct EmptyStore;
        impl JournalStorage for EmptyStore {
            fn read_text(&self) -> Result<Option<String>, String> {
                Ok(Some("[]".into()))
            }
            fn write_bytes(&self, _: &[u8]) -> Result<(), String> {
                panic!("nothing to retire")
            }
        }
        assert!(!recover_at(&EmptyStore, |_| panic!("no recorded interface to restore")).unwrap());
    }

    #[test]
    fn a_full_recovery_journal_never_loses_an_original_or_changes_another_interface() {
        let dir = Fixture::new();
        let path = dir.path();
        let originals = (1..=MAX_RECORDS)
            .map(|id| original(id as u128))
            .collect::<Vec<_>>();
        write(&path, &originals).unwrap();
        assert!(
            record_before_change(&path, original(1000), || panic!(
                "no durable space for original"
            ))
            .is_err()
        );
        assert_eq!(read(&path).unwrap(), originals);
    }

    #[test]
    fn a_skipped_setter_does_not_leave_an_owned_policy_record() {
        let dir = Fixture::new();
        let path = dir.path();
        write(&path, &[original(1)]).unwrap();
        assert!(!record_before_change(&path, original(2), || Ok(false)).unwrap());
        assert_eq!(read(&path).unwrap(), vec![original(1)]);
    }

    #[test]
    fn an_unplugged_interface_does_not_hide_or_erase_another_original() {
        let dir = Fixture::new();
        let path = dir.path();
        write(&path, &[original(1), original(2)]).unwrap();
        let mut visited = Vec::new();
        assert!(
            recover_at(&path, |entry| {
                visited.push(entry.interface_guid.clone());
                if *entry == original(1) {
                    Err("interface unplugged".into())
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        assert_eq!(visited.len(), 2);
        assert_eq!(read(&path).unwrap(), vec![original(1)]);
        record_before_change(&path, original(3), || Ok(true)).unwrap();
        assert_eq!(read(&path).unwrap(), vec![original(1), original(3)]);
        recover_at(&path, |_| Ok(())).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn invalid_and_duplicate_originals_cannot_drive_native_recovery() {
        let dir = Fixture::new();
        let path = dir.path();
        for records in [
            vec![original(0)],
            vec![original(1), original(1)],
            vec![Original {
                original_ignore_default_routes: true,
                ..original(1)
            }],
        ] {
            let bytes = serde_json::to_vec(&records).unwrap();
            fs::write(&path, &bytes).unwrap();
            assert!(
                recover_at(&path, |_| panic!("invalid original must not reach Windows")).is_err()
            );
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
    }

    #[test]
    #[ignore = "Read-only native IPv6 API smoke; needs an installed IPv6 stack, never sets policy"]
    fn native_ipv6_interface_and_route_queries_are_read_only() {
        use windows::Win32::NetworkManagement::IpHelper::{
            GetIpInterfaceTable, MIB_IPINTERFACE_TABLE,
        };
        struct Table(*mut MIB_IPINTERFACE_TABLE);
        impl Drop for Table {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe { FreeMibTable(self.0.cast()) }
                }
            }
        }
        let mut pointer = std::ptr::null_mut();
        let result = unsafe { GetIpInterfaceTable(AF_INET6, &mut pointer) };
        let table = Table(pointer);
        status(result, "Read IPv6 interface table").unwrap();
        assert!(!table.0.is_null());
        let count = unsafe { (*table.0).NumEntries } as usize;
        assert!((1..=65536).contains(&count));
        let rows = unsafe { std::ptr::addr_of!((*table.0).Table).cast::<MIB_IPINTERFACE_ROW>() };
        for index in 0..count {
            let row = unsafe { &*rows.add(index) };
            let mut guid = GUID::zeroed();
            status(
                unsafe { ConvertInterfaceLuidToGuid(&row.InterfaceLuid, &mut guid) },
                "Read interface identity",
            )
            .unwrap();
            let current = interface_for_guid(&guid).unwrap();
            assert_eq!(current.InterfaceIndex, row.InterfaceIndex);
            assert_eq!(current.Family, AF_INET6);
            default_origins(&current).unwrap();
        }
        eprintln!(
            "Verified {count} native IPv6 interface identities and route queries; no setters called"
        );
    }
}
