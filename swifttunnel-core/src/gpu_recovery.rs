//! Durable runtime GPU originals, scoped to one process and tuning lease.
//! Registry operations remain with the caller; file transactions serialize
//! clients and never replace unreadable recovery data with an empty record.
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Owner {
    pub pid: u32,
    pub created: u64,
    pub lease: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Change {
    pub name: String,
    pub original: Option<String>,
    pub applied: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Record {
    owner: Owner,
    entries: HashMap<String, Change>,
}
pub(crate) struct Journal {
    path: PathBuf,
    owner: Owner,
}
const MAX_BYTES: usize = 256 * 1024;

fn location() -> Result<PathBuf, String> {
    dirs::config_dir()
        .map(|path| path.join("SwiftTunnel/process_gpu_recovery.json"))
        .ok_or_else(|| "Could not find the GPU recovery folder".into())
}
fn owner_alive(owner: &Owner) -> Result<bool, String> {
    use windows::Win32::{
        Foundation::{CloseHandle, ERROR_INVALID_PARAMETER},
        System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    };
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, owner.pid) } {
        Ok(handle) => handle,
        Err(error) if error.code() == ERROR_INVALID_PARAMETER.to_hresult() => return Ok(false),
        Err(error) => return Err(format!("Could not verify GPU recovery owner: {error}")),
    };
    let created = crate::process_snapshot::creation_time(handle);
    unsafe {
        let _ = CloseHandle(handle);
    }
    created.map(|created| created == owner.created)
}
fn key(name: &str) -> String {
    name.replace('/', "\\").to_ascii_lowercase()
}

fn valid_change(change: &Change) -> bool {
    Path::new(&change.name).is_absolute()
        && !change.name.contains('\0')
        && Path::new(&change.name)
            .extension()
            .is_some_and(|ext| ext.to_string_lossy().eq_ignore_ascii_case("exe"))
        && (change.applied.encode_utf16().count() + 1) * 2 <= crate::registry_value::MAX_VALUE_BYTES
        && change.original.as_ref().is_none_or(|value| {
            (value.encode_utf16().count() + 1) * 2 <= crate::registry_value::MAX_VALUE_BYTES
        })
}

fn read(path: &Path) -> Result<Option<Record>, String> {
    let bytes = match crate::utils::read_text_file_bounded(path, MAX_BYTES, "Runtime GPU recovery")
    {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let record: Record = serde_json::from_str(&bytes).map_err(|error| {
        format!("GPU recovery data could not be read; original file kept: {error}")
    })?;
    if record.owner.pid == 0
        || record.owner.created == 0
        || record.owner.lease.len() != 32
        || !record
            .owner
            .lease
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || record.entries.len() > 1024
        || record
            .entries
            .iter()
            .any(|(entry_key, change)| entry_key != &key(&change.name) || !valid_change(change))
    {
        return Err("GPU recovery data contains invalid entries; original file kept".into());
    }
    Ok(Some(record))
}
fn lock(path: &Path) -> Result<fs::File, String> {
    use std::os::windows::fs::OpenOptionsExt;
    let parent = path.parent().ok_or("Invalid GPU recovery path")?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let path = path.with_extension("lock");
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        use std::os::windows::fs::MetadataExt;
        if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 {
            return Err("A redirected GPU recovery lock was left untouched".into());
        }
    }
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(path)
        .map_err(|error| format!("GPU recovery is busy or unavailable: {error}"))
}
fn write(path: &Path, record: &Record) -> Result<(), String> {
    if record.entries.is_empty() {
        return match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.to_string()),
        };
    }
    if read(path)?.as_ref() == Some(record) {
        return Ok(());
    }
    let bytes = serde_json::to_vec(record).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_BYTES {
        return Err("GPU recovery data exceeds its size limit".into());
    }
    let temporary = path.with_extension(format!(
        "{}.{:032x}.tmp",
        std::process::id(),
        rand::random::<u128>()
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    let result = (|| -> std::io::Result<()> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|error| error.to_string())
}
fn restore_record(
    path: &Path,
    record: &mut Record,
    restore: &mut impl FnMut(&Change) -> Result<(), String>,
) -> Result<usize, String> {
    let mut restored = 0;
    let mut failures = Vec::new();
    record.entries.retain(|_, entry| match restore(entry) {
        Ok(()) => {
            restored += 1;
            false
        }
        Err(error) => {
            failures.push(error);
            true
        }
    });
    write(path, record)?;
    if failures.is_empty() {
        Ok(restored)
    } else {
        Err(format!(
            "GPU restore has pending originals: {}",
            failures.join("; ")
        ))
    }
}
impl Journal {
    pub(crate) fn new() -> Result<Self, String> {
        use windows::Win32::System::Threading::GetCurrentProcess;
        Ok(Self {
            path: location()?,
            owner: Owner {
                pid: std::process::id(),
                created: crate::process_snapshot::creation_time(unsafe { GetCurrentProcess() })?,
                lease: format!("{:032x}", rand::random::<u128>()),
            },
        })
    }
    pub(crate) fn prepare(
        &self,
        change: Change,
        mut restore: impl FnMut(&Change) -> Result<(), String>,
    ) -> Result<Change, String> {
        self.prepare_with(change, owner_alive, &mut restore)
    }
    fn prepare_with(
        &self,
        change: Change,
        alive: impl FnOnce(&Owner) -> Result<bool, String>,
        restore: &mut impl FnMut(&Change) -> Result<(), String>,
    ) -> Result<Change, String> {
        if !valid_change(&change) {
            return Err(
                "GPU change could not be recorded safely; setting was left unchanged".into(),
            );
        }
        let _guard = lock(&self.path)?;
        let mut record = read(&self.path)?.unwrap_or_else(|| Record {
            owner: self.owner.clone(),
            entries: HashMap::new(),
        });
        if record.owner != self.owner {
            if alive(&record.owner)? {
                return Err("GPU originals belong to another active or pending tuning lease; they were left untouched".into());
            }
            restore_record(&self.path, &mut record, restore)?;
            record.owner = self.owner.clone();
        }
        let key = key(&change.name);
        if let Some(existing) = record.entries.get(&key) {
            if existing.applied != change.applied {
                return Err("An earlier GPU change still needs recovery".into());
            }
            return Ok(existing.clone());
        }
        record.entries.insert(key, change.clone());
        write(&self.path, &record)?; // Every original is durable before apply.
        Ok(change)
    }
    pub(crate) fn release(
        &self,
        name: &str,
        restore: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        let _guard = lock(&self.path)?;
        let mut record = read(&self.path)?;
        if record
            .as_ref()
            .is_some_and(|record| record.owner != self.owner)
        {
            return Err("GPU recovery ownership changed; setting was left untouched".into());
        }
        restore()?;
        if let Some(record) = &mut record {
            record.entries.remove(&key(name));
            write(&self.path, record)?;
        }
        Ok(())
    }
    pub(crate) fn cleanup(
        &self,
        mut restore: impl FnMut(&Change) -> Result<(), String>,
    ) -> Result<usize, String> {
        let _guard = lock(&self.path)?;
        let Some(mut record) = read(&self.path)? else {
            return Ok(0);
        };
        if record.owner != self.owner {
            return Ok(0);
        }
        restore_record(&self.path, &mut record, &mut restore)
    }
}
pub(crate) fn recover(
    mut restore: impl FnMut(&Change) -> Result<(), String>,
) -> Result<usize, String> {
    recover_at(&location()?, owner_alive, &mut restore)
}
fn recover_at(
    path: &Path,
    alive: impl FnOnce(&Owner) -> Result<bool, String>,
    restore: &mut impl FnMut(&Change) -> Result<(), String>,
) -> Result<usize, String> {
    if read(path)?.is_none() {
        return Ok(0);
    }
    let _guard = lock(path)?;
    let Some(mut record) = read(path)? else {
        return Ok(0);
    };
    if alive(&record.owner)? {
        return Ok(0);
    }
    restore_record(path, &mut record, restore)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_checks_use_creation_time_and_unicode_limits_match_native_registry_data() {
        use windows::Win32::System::Threading::GetCurrentProcess;
        let created =
            crate::process_snapshot::creation_time(unsafe { GetCurrentProcess() }).unwrap();
        let mut owner = Owner {
            pid: std::process::id(),
            created,
            lease: "1".repeat(32),
        };
        assert!(owner_alive(&owner).unwrap());
        owner.created ^= 1;
        assert!(!owner_alive(&owner).unwrap());
        owner.pid = u32::MAX;
        assert!(!owner_alive(&owner).unwrap());
        let journal = fixture();
        let mut entry = change("Unicode");
        entry.original = Some("界".repeat(24000));
        assert!(valid_change(&entry));
        journal
            .prepare_with(entry.clone(), |_| Ok(false), &mut |_| Ok(()))
            .unwrap();
        assert_eq!(
            read(&journal.path).unwrap().unwrap().entries[&key(&entry.name)],
            entry
        );
        entry.applied = "x".repeat(40000);
        assert!(
            journal
                .prepare_with(entry, |_| Ok(false), &mut |_| Ok(()))
                .is_err()
        );
        clean(journal);
    }
    fn fixture() -> Journal {
        let root =
            std::env::temp_dir().join(format!("swift-gpu-journal-{:032x}", rand::random::<u128>()));
        fs::create_dir(&root).unwrap();
        Journal {
            path: root.join("recovery.json"),
            owner: Owner {
                pid: 1,
                created: 2,
                lease: "1".repeat(32),
            },
        }
    }
    fn change(name: &str) -> Change {
        Change {
            name: format!(r"C:\Games\{name}.exe"),
            original: Some("GpuPreference=1;".into()),
            applied: "GpuPreference=2;".into(),
        }
    }
    fn clean(journal: Journal) {
        let _ = fs::remove_file(&journal.path);
        let _ = fs::remove_file(journal.path.with_extension("lock"));
        fs::remove_dir(journal.path.parent().unwrap()).unwrap();
    }
    #[test]
    fn originals_are_durable_before_apply_and_failed_recovery_survives_dropping_memory() {
        let journal = fixture();
        journal
            .prepare_with(change("A"), |_| Ok(false), &mut |_| Ok(()))
            .unwrap();
        journal
            .prepare_with(change("B"), |_| Ok(false), &mut |_| Ok(()))
            .unwrap();
        assert_eq!(read(&journal.path).unwrap().unwrap().entries.len(), 2);
        assert!(
            recover_at(
                &journal.path,
                |_| Ok(false),
                &mut |entry| if entry.name.ends_with("A.exe") {
                    Ok(())
                } else {
                    Err("Read denied".into())
                }
            )
            .is_err()
        );
        assert_eq!(read(&journal.path).unwrap().unwrap().entries.len(), 1);
        assert_eq!(
            recover_at(&journal.path, |_| Ok(false), &mut |_| Ok(())).unwrap(),
            1
        );
        assert!(!journal.path.exists());
        clean(journal);
    }
    #[test]
    fn live_owners_corruption_and_concurrent_operations_are_never_overwritten() {
        let journal = fixture();
        journal
            .prepare_with(change("A"), |_| Ok(false), &mut |_| Ok(()))
            .unwrap();
        assert_eq!(
            recover_at(&journal.path, |_| Ok(true), &mut |_| panic!(
                "A running client's value must not change"
            ))
            .unwrap(),
            0
        );
        let other = Journal {
            path: journal.path.clone(),
            owner: Owner {
                lease: "2".repeat(32),
                ..journal.owner.clone()
            },
        };
        assert!(
            other
                .prepare_with(change("B"), |_| Ok(true), &mut |_| panic!(
                    "No live-owner restore"
                ))
                .is_err()
        );
        assert!(
            other
                .release("A", || panic!(
                    "A new owner cannot undo the old owner's setting"
                ))
                .is_err()
        );
        let guard = lock(&journal.path).unwrap();
        assert!(lock(&journal.path).is_err());
        drop(guard);
        fs::write(&journal.path, "damaged journal").unwrap();
        assert!(
            journal
                .prepare_with(change("B"), |_| Ok(false), &mut |_| Ok(()))
                .is_err()
        );
        assert_eq!(
            fs::read_to_string(&journal.path).unwrap(),
            "damaged journal"
        );
        clean(journal);
    }
    #[test]
    fn failed_atomic_replacement_keeps_the_original_and_cleans_only_its_temp_file() {
        use std::os::windows::fs::OpenOptionsExt;
        let journal = fixture();
        journal
            .prepare_with(change("A"), |_| Ok(false), &mut |_| Ok(()))
            .unwrap();
        let original = read(&journal.path).unwrap().unwrap();
        let mut next = original.clone();
        next.entries.insert(key(&change("B").name), change("B"));
        let locked = fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&journal.path)
            .unwrap();
        assert!(write(&journal.path, &next).is_err());
        assert_eq!(read(&journal.path).unwrap().unwrap(), original);
        assert_eq!(
            fs::read_dir(journal.path.parent().unwrap())
                .unwrap()
                .count(),
            2
        ); // Record and lock, no temp leak.
        drop(locked);
        write(&journal.path, &next).unwrap();
        clean(journal);
    }
}
