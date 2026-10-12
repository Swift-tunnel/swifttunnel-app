//! Remove unsupported flag overrides with an exact local backup and guarded undo.
use crate::roblox_optimizer::RobloxOptimizer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Default, Serialize)]
pub struct FlagCleanupReport {
    pub files_changed: usize,
    pub flags_removed: usize,
    pub skipped: Vec<String>,
    pub can_undo: bool,
}
#[derive(Serialize, Deserialize)]
struct Backup {
    path: PathBuf,
    before: String,
    after: String,
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn root() -> Result<PathBuf, String> {
    dirs::config_dir()
        .map(|p| p.join("SwiftTunnel").join("flag-backups"))
        .ok_or("Windows could not find your settings folder.".into())
}
fn safe(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    path.ancestors()
        .all(|part| match fs::symlink_metadata(part) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return false;
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if meta.file_attributes() & 0x400 != 0 {
                        return false;
                    }
                }
                true
            }
            Err(_) => false,
        })
}
fn read(path: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(256 * 1024 + 1).read_to_end(&mut bytes))
        .map_err(|e| e.to_string())?;
    if bytes.len() > 256 * 1024 {
        return Err("Flag file exceeds 256 KB.".into());
    }
    Ok(bytes)
}
fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if !safe(path.parent().ok_or("Invalid flag-file location.")?) {
        return Err("The flag folder is redirected; it was left untouched.".into());
    }
    let temporary = path.with_extension(format!("{}.flags.tmp", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|e| e.to_string())?;
    let result = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|e| e.to_string())
}
fn stopped() -> Result<(), String> {
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    if system
        .processes()
        .values()
        .any(|p| crate::process_names::is_roblox_process_name(&p.name().to_string_lossy()))
    {
        return Err("Close Roblox Player and Studio before changing flag files.".into());
    }
    Ok(())
}
struct Change {
    path: PathBuf,
    original: Vec<u8>,
    updated: Vec<u8>,
    removed: usize,
}
fn plan(paths: &[PathBuf]) -> Result<(Vec<Change>, Vec<String>), String> {
    let mut changes = Vec::new();
    let mut skipped = Vec::new();
    let mut total = 0;
    for path in paths.iter().take(64) {
        if !safe(path) {
            skipped.push("A redirected flag file was left untouched.".into());
            continue;
        }
        let bytes = match read(path) {
            Ok(bytes) => bytes,
            Err(error) => {
                skipped.push(error);
                continue;
            }
        };
        total += bytes.len();
        if total > 2 * 1024 * 1024 {
            return Err(
                "Flag cleanup exceeds its 2 MB backup limit. Clean older Roblox versions first."
                    .into(),
            );
        }
        let raw = match std::str::from_utf8(&bytes) {
            Ok(raw) => raw,
            Err(_) => {
                skipped.push("An unreadable flag file was left untouched.".into());
                continue;
            }
        };
        let preview = RobloxOptimizer::preview_flag_import("Existing flags", raw);
        if let Some(error) = preview.error {
            skipped.push(error);
            continue;
        }
        if !preview.skipped.is_empty() {
            changes.push(Change {
                path: path.clone(),
                original: bytes,
                updated: preview.json.into_bytes(),
                removed: preview.skipped.len(),
            });
        }
    }
    if paths.len() > 64 {
        skipped
            .push("More than 64 flag files were found; only the first 64 were inspected.".into());
    }
    Ok((changes, skipped))
}
pub fn preview() -> Result<FlagCleanupReport, String> {
    let files = RobloxOptimizer::existing_client_flag_files().map_err(|e| e.to_string())?;
    let (changes, skipped) = plan(&files)?;
    Ok(FlagCleanupReport {
        files_changed: changes.len(),
        flags_removed: changes.iter().map(|c| c.removed).sum(),
        skipped,
        can_undo: root()?.join("index.json").exists(),
    })
}
fn clean_in(paths: &[PathBuf], backups: &Path) -> Result<FlagCleanupReport, String> {
    let (changes, skipped) = plan(paths)?;
    let mut report = FlagCleanupReport {
        skipped,
        can_undo: backups.join("index.json").exists(),
        ..Default::default()
    };
    if changes.is_empty() {
        return Ok(report);
    }
    fs::create_dir_all(backups).map_err(|e| e.to_string())?;
    if !safe(backups) {
        return Err("The backup folder is redirected. No flag files were changed.".into());
    }
    let mut manifest = Vec::new();
    for change in &changes {
        let before = digest(&change.original);
        let after = digest(&change.updated);
        write(&backups.join(format!("{before}.json")), &change.original)?;
        manifest.push(Backup {
            path: change.path.clone(),
            before,
            after,
        });
    }
    // Publish undo information before touching the first flag file. A crash
    // can leave a partial cleanup, but every changed file remains recoverable.
    write(
        &backups.join("index.json"),
        &serde_json::to_vec(&manifest).map_err(|e| e.to_string())?,
    )?;
    for change in changes {
        if read(&change.path).is_ok_and(|current| digest(&current) == digest(&change.original)) {
            match write(&change.path, &change.updated) {
                Ok(()) => {
                    report.files_changed += 1;
                    report.flags_removed += change.removed;
                }
                Err(error) => report.skipped.push(error),
            }
        } else {
            report
                .skipped
                .push("A flag file changed after the preview; it was left untouched.".into());
        }
    }
    report.can_undo = true;
    // Keep only the current undo set. Never touch files outside this folder or
    // files whose names do not match the backup format.
    if let Ok(entries) = fs::read_dir(backups) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.len() == 69
                && name.ends_with(".json")
                && name[..64].bytes().all(|b| b.is_ascii_hexdigit())
                && !manifest
                    .iter()
                    .any(|b| name == format!("{}.json", b.before))
                && safe(&entry.path())
            {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    Ok(report)
}
pub fn clean() -> Result<FlagCleanupReport, String> {
    stopped()?;
    clean_in(
        &RobloxOptimizer::existing_client_flag_files().map_err(|e| e.to_string())?,
        &root()?,
    )
}
fn undo_in(paths: &[PathBuf], backups: &Path) -> Result<FlagCleanupReport, String> {
    let manifest: Vec<Backup> = serde_json::from_slice(&read(&backups.join("index.json"))?)
        .map_err(|_| "The undo backup could not be read safely.".to_string())?;
    if manifest.len() > 64
        || manifest.iter().any(|b| {
            b.before.len() != 64
                || b.after.len() != 64
                || !b.before.bytes().all(|c| c.is_ascii_hexdigit())
                || !b.after.bytes().all(|c| c.is_ascii_hexdigit())
        })
    {
        return Err("Invalid undo manifest. No files were changed.".into());
    }
    let mut report = FlagCleanupReport::default();
    let mut remaining = Vec::new();
    for backup in manifest {
        if !paths.contains(&backup.path) || !safe(&backup.path) {
            report.skipped.push(
                "A flag file is no longer installed at its original location; its backup was kept."
                    .into(),
            );
            remaining.push(backup);
            continue;
        }
        let current = read(&backup.path)?;
        if digest(&current) == backup.before {
            continue;
        }
        if digest(&current) != backup.after {
            report.skipped.push(
                "A flag file was edited after cleanup; undo preserved your newer changes.".into(),
            );
            remaining.push(backup);
            continue;
        }
        let original = read(&backups.join(format!("{}.json", backup.before)))?;
        if digest(&original) != backup.before {
            return Err("An undo backup failed its integrity check. It was not applied.".into());
        }
        write(&backup.path, &original)?;
        report.files_changed += 1;
    }
    if remaining.is_empty() {
        fs::remove_file(backups.join("index.json")).map_err(|e| e.to_string())?;
    } else {
        write(
            &backups.join("index.json"),
            &serde_json::to_vec(&remaining).map_err(|e| e.to_string())?,
        )?;
    }
    report.can_undo = !remaining.is_empty();
    Ok(report)
}
pub fn undo() -> Result<FlagCleanupReport, String> {
    if !root()?.join("index.json").exists() {
        return Err("There is no flag cleanup backup to undo.".into());
    }
    stopped()?;
    undo_in(
        &RobloxOptimizer::existing_client_flag_files().map_err(|e| e.to_string())?,
        &root()?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cleanup_backs_up_original_bytes_and_undo_preserves_newer_edits() {
        let dir = std::env::temp_dir().join(format!("swift-flag-undo-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("ClientAppSettings.json");
        let backups = dir.join("backups");
        let original = br#"{"FFlagDebugGraphicsPreferD3D11":true,"FFlagOldUnsupportedFlag":true}"#;
        fs::write(&file, original).unwrap();
        let report = clean_in(&[file.clone()], &backups).unwrap();
        assert_eq!((report.files_changed, report.flags_removed), (1, 1));
        let cleaned = fs::read(&file).unwrap();
        fs::write(&file, b"{\"user_changed\":true}").unwrap();
        assert_eq!(undo_in(&[file.clone()], &backups).unwrap().files_changed, 0);
        assert_eq!(fs::read(&file).unwrap(), b"{\"user_changed\":true}");
        fs::write(&file, cleaned).unwrap();
        assert_eq!(undo_in(&[file.clone()], &backups).unwrap().files_changed, 1);
        assert_eq!(fs::read(&file).unwrap(), original);
        fs::remove_dir_all(dir).unwrap();
    }
}
