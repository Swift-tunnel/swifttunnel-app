//! Launch the official installed player without invoking a strap's URI handler.
use crate::roblox_library::{RobloxClient, join_url};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub fn official_player() -> Result<PathBuf, String> {
    let root = std::env::var_os("LOCALAPPDATA")
        .ok_or("Windows could not find the Roblox installation.")?;
    find_player(&PathBuf::from(root).join("Roblox/Versions"))
}
pub fn updater_running() -> bool {
    let Some(root) = std::env::var_os("LOCALAPPDATA") else {
        return false;
    };
    let root = PathBuf::from(root).join("Roblox");
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    system.processes().values().any(|p| {
        matches!(
            p.name().to_string_lossy().as_ref(),
            "RobloxPlayerInstaller.exe" | "RobloxInstaller.exe" | "RobloxPlayerLauncher.exe"
        ) && p.exe().is_some_and(|p| p.starts_with(&root))
    })
}
fn find_player(versions: &Path) -> Result<PathBuf, String> {
    let mut players = Vec::new();
    if let Ok(entries) = fs::read_dir(versions) {
        for entry in entries.flatten().take(256) {
            if !entry.file_name().to_string_lossy().starts_with("version-") {
                continue;
            }
            let path = entry.path().join("RobloxPlayerBeta.exe");
            if safe_path(&path).is_ok()
                && let Ok(metadata) = fs::metadata(&path)
                && metadata.is_file()
                && metadata.len() > 0
            {
                players.push((metadata.modified().ok(), path));
            }
        }
    }
    players.sort_by(|a, b| b.cmp(a));
    players.into_iter().next().map(|(_,p)| p).ok_or_else(|| "Install the official Roblox player from roblox.com first. SwiftTunnel Play uses Roblox directly; Roblox handles its own updates.".into())
}
pub fn safe_path(path: &Path) -> Result<(), String> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) => {
                let mut redirected = meta.file_type().is_symlink();
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    redirected |= meta.file_attributes() & 0x400 != 0;
                }
                if redirected {
                    return Err("A redirected Roblox installation was left untouched.".into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}
pub fn launch(player: &Path, place: &str, job: Option<&str>) -> Result<u32, String> {
    let uri = join_url(place, job, RobloxClient::Standard)?;
    if player
        .file_name()
        .is_none_or(|n| n != "RobloxPlayerBeta.exe")
    {
        return Err("Choose the official Roblox player.".into());
    }
    safe_path(player)?;
    Command::new(player)
        .arg(uri)
        .current_dir(player.parent().ok_or("Invalid Roblox installation.")?)
        .spawn()
        .map(|child| child.id())
        .map_err(|e| format!("Roblox could not start: {e}"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolver_excludes_studio_and_other_launcher_roots() {
        let root = std::env::temp_dir().join(format!("swift-native-{}", std::process::id()));
        fs::create_dir_all(root.join("version-player")).unwrap();
        fs::create_dir_all(root.join("version-studio")).unwrap();
        fs::write(root.join("version-player/RobloxPlayerBeta.exe"), b"fixture").unwrap();
        fs::write(root.join("version-studio/RobloxStudioBeta.exe"), b"fixture").unwrap();
        assert_eq!(
            find_player(&root).unwrap(),
            root.join("version-player/RobloxPlayerBeta.exe")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
