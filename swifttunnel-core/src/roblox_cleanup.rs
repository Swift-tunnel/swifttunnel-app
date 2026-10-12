//! Explicit, bounded cleanup of old Roblox player logs and cached asset blobs.
//! Never follows junctions or accepts a caller-supplied filesystem path.
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupKind {
    Logs,
    Assets,
}
#[derive(Default, Serialize)]
pub struct CleanupReport {
    pub files: u64,
    pub bytes: u64,
    pub skipped: u64,
    pub partial: bool,
}

fn is_link(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    false
}

fn safe_path(base: &Path, path: &Path) -> bool {
    if !path.starts_with(base) {
        return false;
    }
    for parent in path.ancestors() {
        if !parent.starts_with(base) {
            break;
        }
        match fs::symlink_metadata(parent) {
            Ok(m) if !is_link(&m) => {}
            _ => return false,
        }
    }
    true
}

fn eligible_name(path: &Path, kind: CleanupKind) -> bool {
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    match kind {
        CleanupKind::Logs => name.ends_with(".log") && name.contains("player"),
        // Cached content hashes and image/mesh blobs only. Preserve databases,
        // cookies, configuration and identifiers even inside cache directories.
        CleanupKind::Assets => {
            (32..=64).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_hexdigit())
                || ["png", "jpg", "jpeg", "webp", "ktx", "mesh"].contains(
                    &path
                        .extension()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_ascii_lowercase()
                        .as_str(),
                )
        }
    }
}

pub fn inspect(kind: CleanupKind, delete: bool) -> Result<CleanupReport, String> {
    if delete {
        let mut system = sysinfo::System::new();
        system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        if system
            .processes()
            .values()
            .any(|p| crate::process_names::is_roblox_process_name(&p.name().to_string_lossy()))
        {
            return Err(
                "Close Roblox Player and Studio before cleaning their files, then try again."
                    .into(),
            );
        }
    }
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or("Windows could not find your app-data folder.")?;
    if !base.is_absolute() {
        return Err("Windows returned an invalid app-data folder.".into());
    }
    inspect_in(&base, kind, delete, SystemTime::now())
}

fn inspect_in(
    base: &Path,
    kind: CleanupKind,
    delete: bool,
    now: SystemTime,
) -> Result<CleanupReport, String> {
    let mut report = CleanupReport::default();
    let mut stack = Vec::new();
    for client in ["Roblox", "RobloxPCVNG"] {
        let root = base.join(client).join(match kind {
            CleanupKind::Logs => "logs",
            CleanupKind::Assets => "rbx-storage",
        });
        if root.exists() {
            if !safe_path(base, &root) {
                return Err("A Roblox cleanup folder is redirected. Cleanup was stopped to protect other files.".into());
            }
            stack.push((root, 0));
        }
    }
    let cutoff = now
        .checked_sub(Duration::from_secs(7 * 24 * 60 * 60))
        .ok_or("Could not calculate the cleanup age.")?;
    let mut inspected = 0;
    while let Some((dir, depth)) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => {
                report.skipped += 1;
                continue;
            }
        };
        for entry in entries {
            inspected += 1;
            if inspected > 50_000 {
                report.partial = true;
                return Ok(report);
            }
            let Ok(entry) = entry else {
                report.skipped += 1;
                continue;
            };
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                report.skipped += 1;
                continue;
            };
            if is_link(&meta) {
                report.skipped += 1;
                continue;
            }
            if meta.is_dir() {
                if depth < 8 {
                    stack.push((path, depth + 1));
                } else {
                    report.partial = true;
                }
                continue;
            }
            if !meta.is_file()
                || !eligible_name(&path, kind)
                || !meta.modified().is_ok_and(|date| date < cutoff)
            {
                continue;
            }
            if delete && (!safe_path(base, &path) || fs::remove_file(&path).is_err()) {
                report.skipped += 1;
                continue;
            }
            report.files += 1;
            report.bytes = report.bytes.saturating_add(meta.len());
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_explicit_old_asset_blobs_are_removed_and_settings_survive() {
        let base = std::env::temp_dir().join(format!("swift-cleanup-{}", std::process::id()));
        let cache = base.join("Roblox").join("rbx-storage");
        fs::create_dir_all(&cache).unwrap();
        let asset = cache.join("0123456789abcdef0123456789abcdef");
        fs::write(&asset, b"image").unwrap();
        fs::write(cache.join("cookies.json"), b"keep").unwrap();
        fs::write(cache.join("rbx-storage.db"), b"keep").unwrap();
        fs::write(
            base.join("Roblox").join("GlobalBasicSettings_13.xml"),
            b"keep",
        )
        .unwrap();
        let future = SystemTime::now() + Duration::from_secs(8 * 24 * 60 * 60);
        let preview = inspect_in(&base, CleanupKind::Assets, false, future).unwrap();
        assert_eq!((preview.files, preview.bytes), (1, 5));
        assert!(asset.exists());
        let report = inspect_in(&base, CleanupKind::Assets, true, future).unwrap();
        assert_eq!(report.files, 1);
        assert!(!asset.exists());
        assert!(cache.join("cookies.json").exists());
        assert!(cache.join("rbx-storage.db").exists());
        assert!(
            base.join("Roblox")
                .join("GlobalBasicSettings_13.xml")
                .exists()
        );
        fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn recent_files_and_studio_logs_are_preserved() {
        assert!(!eligible_name(
            Path::new("Roblox_Studio.log"),
            CleanupKind::Logs
        ));
        assert!(eligible_name(
            Path::new("Roblox_Player.log"),
            CleanupKind::Logs
        ));
        let base =
            std::env::temp_dir().join(format!("swift-cleanup-recent-{}", std::process::id()));
        let logs = base.join("Roblox").join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(logs.join("Roblox_Player.log"), b"recent").unwrap();
        assert_eq!(
            inspect_in(&base, CleanupKind::Logs, true, SystemTime::now())
                .unwrap()
                .files,
            0
        );
        assert!(logs.join("Roblox_Player.log").exists());
        fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn path_checks_reject_any_target_outside_the_known_base() {
        let base =
            std::env::temp_dir().join(format!("swift-cleanup-boundary-{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        assert!(!safe_path(
            &base,
            &std::env::temp_dir().join("some-other-app")
        ));
        assert!(!eligible_name(
            Path::new("settings.json"),
            CleanupKind::Assets
        ));
        assert!(!eligible_name(
            Path::new("rbx-storage.db"),
            CleanupKind::Assets
        ));
        fs::remove_dir(base).unwrap();
    }
}
