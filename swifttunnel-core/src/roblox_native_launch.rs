//! Launch the official installed player without invoking a strap's URI handler.
use crate::roblox_library::{RobloxClient, join_url};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub fn official_player() -> Result<PathBuf, String> {
    official_player_for(RobloxClient::Standard)
}
pub fn installation_root(base: &Path, client: RobloxClient) -> PathBuf {
    base.join(match client {
        RobloxClient::Standard => "Roblox",
        RobloxClient::Vng => "RobloxPCVNG",
    })
}
pub fn official_player_for(client: RobloxClient) -> Result<PathBuf, String> {
    let root = std::env::var_os("LOCALAPPDATA")
        .ok_or("Windows could not find the Roblox installation.")?;
    find_player_for(&PathBuf::from(root), client)
}
pub fn installed_clients() -> Result<Vec<RobloxClient>, String> {
    let base = std::env::var_os("LOCALAPPDATA")
        .ok_or("Windows could not find the Roblox installation.")?;
    Ok(installed_clients_at(Path::new(&base)))
}
fn installed_clients_at(base: &Path) -> Vec<RobloxClient> {
    [RobloxClient::Standard, RobloxClient::Vng]
        .into_iter()
        .filter(|client| find_player(&installation_root(base, *client).join("Versions")).is_ok())
        .collect()
}
fn find_player_for(base: &Path, client: RobloxClient) -> Result<PathBuf, String> {
    find_player(&installation_root(base, client).join("Versions")).map_err(|_| {
        let other = match client {
            RobloxClient::Standard => RobloxClient::Vng,
            RobloxClient::Vng => RobloxClient::Standard,
        };
        if find_player(&installation_root(base, other).join("Versions")).is_ok() {
            return match client {
                RobloxClient::Standard => "This game is set to Roblox, but only Roblox VNG was found. Use Change player to add it with Roblox VNG.".into(),
                RobloxClient::Vng => "This game is set to Roblox VNG, but only Roblox was found. Use Change player to add it with Roblox.".into(),
            };
        }
        match client {
            RobloxClient::Standard => "Install Roblox from roblox.com first.".into(),
            RobloxClient::Vng => "Install Roblox VNG from robloxapp.vnggames.com first.".into(),
        }
    })
}
pub fn updater_running() -> bool {
    let Some(root) = std::env::var_os("LOCALAPPDATA") else {
        return false;
    };
    let base = PathBuf::from(root);
    #[cfg(windows)]
    {
        let Ok(processes) = crate::process_snapshot::list_named(&[
            "RobloxPlayerInstaller.exe",
            "RobloxInstaller.exe",
            "RobloxPlayerLauncher.exe",
        ]) else {
            return false;
        };
        processes.iter().any(|process| {
            crate::process_snapshot::image_path(process.pid)
                .ok()
                .flatten()
                .is_some_and(|image| updater_image_is_installed(&base, Path::new(&image)))
        })
    }
    #[cfg(not(windows))]
    {
        let roots = [RobloxClient::Standard, RobloxClient::Vng]
            .map(|client| installation_root(&base, client));
        let mut system = sysinfo::System::new();
        system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        system.processes().values().any(|p| {
            matches!(
                p.name().to_string_lossy().as_ref(),
                "RobloxPlayerInstaller.exe" | "RobloxInstaller.exe" | "RobloxPlayerLauncher.exe"
            ) && p
                .exe()
                .is_some_and(|p| roots.iter().any(|root| p.starts_with(root)))
        })
    }
}
#[cfg(windows)]
fn updater_image_is_installed(base: &Path, image: &Path) -> bool {
    // Process image paths and LOCALAPPDATA can preserve different casing.
    // Use the same case-insensitive, directory-bounded match as the player.
    client_for_image(base, image).is_some()
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
    players
        .into_iter()
        .next()
        .map(|(_, p)| p)
        .ok_or_else(|| "Install Roblox from roblox.com first.".into())
}
pub fn safe_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| part == std::path::Component::ParentDir)
    {
        return Err("This file location is invalid. Reopen SwiftTunnel and try again.".into());
    }
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

fn client_for_image(base: &Path, image: &Path) -> Option<RobloxClient> {
    if !base.is_absolute()
        || !image.is_absolute()
        || image
            .components()
            .any(|part| part == std::path::Component::ParentDir)
    {
        return None;
    }
    [RobloxClient::Standard, RobloxClient::Vng]
        .into_iter()
        .find(|client| {
            let root = installation_root(base, *client);
            let mut image = image.components();
            root.components().all(|part| {
                image.next().is_some_and(|candidate| {
                    crate::utils::same_path_part(part.as_os_str(), candidate.as_os_str())
                })
            }) && image.next().is_some()
        })
}

pub fn running_client() -> Result<Option<RobloxClient>, String> {
    #[cfg(windows)]
    {
        let base = std::env::var_os("LOCALAPPDATA")
            .ok_or("Windows could not find the Roblox installation.")?;
        for process in
            crate::process_snapshot::list_named(crate::process_names::ROBLOX_PLAYER_PROCESS_NAMES)?
        {
            if let Some(image) = crate::process_snapshot::image_path(process.pid)?
                && let Some(client) = client_for_image(Path::new(&base), Path::new(&image))
            {
                return Ok(Some(client));
            }
        }
        Ok(None)
    }
    #[cfg(not(windows))]
    {
        Ok(None)
    }
}

fn player_command(player: &Path) -> Result<Command, String> {
    if player
        .file_name()
        .is_none_or(|name| name != "RobloxPlayerBeta.exe")
    {
        return Err("Choose the official Roblox player.".into());
    }
    safe_path(player)?;
    let metadata =
        fs::metadata(player).map_err(|error| format!("Roblox's player is unavailable: {error}"))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err("Roblox's player is unavailable. Wait for its update, then try again.".into());
    }
    let mut command = Command::new(player);
    command.current_dir(player.parent().ok_or("Invalid Roblox installation.")?);
    Ok(command)
}

pub fn open_home(player: &Path) -> Result<u32, String> {
    player_command(player)?
        .spawn()
        .map(|child| child.id())
        .map_err(|error| format!("Roblox could not start: {error}"))
}
pub fn launch(
    player: &Path,
    place: &str,
    job: Option<&str>,
    client: RobloxClient,
) -> Result<u32, String> {
    let uri = join_url(place, job, client)?;
    player_command(player)?
        .arg(uri)
        .spawn()
        .map(|child| child.id())
        .map_err(|e| format!("Roblox could not start: {e}"))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_locations_reject_relative_and_parent_traversal_paths() {
        for path in [
            "",
            "RobloxPlayerBeta.exe",
            r"version-test\RobloxPlayerBeta.exe",
            r"C:RobloxPlayerBeta.exe",
            r"C:\Roblox\..\Other\RobloxPlayerBeta.exe",
        ] {
            assert!(
                safe_path(Path::new(path)).is_err(),
                "accepted ambiguous location: {path}"
            );
        }
        // A checked destination can be created later; absence is not a link.
        let uncreated = std::env::temp_dir().join(format!(
            "swift-safe-location-{:032x}",
            rand::random::<u128>()
        ));
        assert!(safe_path(&uncreated).is_ok());
    }
    #[cfg(windows)]
    #[test]
    fn client_detection_accepts_unicode_casing_but_requires_a_bounded_absolute_path() {
        let base = Path::new(r"E:\Users\Élodie\AppData\Local");
        assert_eq!(
            client_for_image(
                base,
                Path::new(
                    r"e:\users\éLODIE\appdata\local\ROBLOX\Versions\version-test\RobloxPlayerBeta.exe"
                )
            ),
            Some(RobloxClient::Standard)
        );
        assert_eq!(
            client_for_image(
                base,
                Path::new(r"E:/Users/éLODIE/AppData/Local/robloxpcvng/RobloxInstaller.exe")
            ),
            Some(RobloxClient::Vng)
        );
        for invalid in [
            r"E:\Users\Élodie\AppData\Local\Roblox-other\RobloxPlayerBeta.exe",
            r"F:\Users\Élodie\AppData\Local\Roblox\RobloxPlayerBeta.exe",
            r"E:\Users\Élodie\AppData\Local\Roblox\..\Downloads\RobloxPlayerBeta.exe",
            r"E:Users\Élodie\AppData\Local\Roblox\RobloxPlayerBeta.exe",
            r"E:\Users\Élodie\AppData\Local\Roblox",
        ] {
            assert_eq!(
                client_for_image(base, Path::new(invalid)),
                None,
                "{invalid}"
            );
        }
    }
    #[cfg(windows)]
    #[test]
    fn updater_paths_follow_windows_casing_without_accepting_sibling_folders() {
        let base = Path::new(r"E:\Users\Player\AppData\Local");
        assert!(updater_image_is_installed(
            base,
            Path::new(
                r"e:\users\PLAYER\appdata\local\ROBLOX\Versions\version-test\RobloxPlayerInstaller.exe"
            )
        ));
        assert!(updater_image_is_installed(
            base,
            Path::new(r"E:\Users\Player\AppData\Local\robloxpcvng\RobloxInstaller.exe")
        ));
        assert!(!updater_image_is_installed(
            base,
            Path::new(r"E:\Users\Player\AppData\Local\Roblox-other\RobloxPlayerInstaller.exe")
        ));
        assert!(!updater_image_is_installed(
            base,
            Path::new(r"E:\Users\Player\AppData\Local\RobloxPCVNG-other\RobloxInstaller.exe")
        ));
        assert!(!updater_image_is_installed(
            base,
            Path::new(r"E:\Downloads\RobloxPlayerInstaller.exe")
        ));
    }
    #[test]
    fn restart_resolves_the_client_and_builds_a_native_command_without_a_protocol_handler() {
        let base =
            std::env::temp_dir().join(format!("swift-restart-{:032x}", rand::random::<u128>()));
        let vng = installation_root(&base, RobloxClient::Vng)
            .join("Versions/version-test/RobloxPlayerBeta.exe");
        fs::create_dir_all(vng.parent().unwrap()).unwrap();
        fs::write(&vng, "fixture").unwrap();
        assert_eq!(client_for_image(&base, &vng), Some(RobloxClient::Vng));
        let standard = installation_root(&base, RobloxClient::Standard)
            .join("Versions/version-test/RobloxPlayerBeta.exe");
        assert_eq!(
            client_for_image(&base, &standard),
            Some(RobloxClient::Standard)
        );
        assert_eq!(
            client_for_image(&base, &base.join("RobloxPCVNG-other/RobloxPlayerBeta.exe")),
            None
        );
        let command = player_command(&vng).unwrap();
        assert_eq!(command.get_program(), vng.as_os_str());
        assert_eq!(command.get_current_dir(), vng.parent());
        assert_eq!(command.get_args().count(), 0);
        assert!(player_command(&base.join("Voidstrap.exe")).is_err());
        fs::remove_file(&vng).unwrap();
        fs::remove_dir(vng.parent().unwrap()).unwrap();
        fs::remove_dir(vng.parent().unwrap().parent().unwrap()).unwrap();
        fs::remove_dir(installation_root(&base, RobloxClient::Vng)).unwrap();
        fs::remove_dir(base).unwrap();
    }
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
    #[test]
    fn vng_and_standard_players_are_resolved_separately() {
        let base = std::env::temp_dir().join(format!("swift-native-vng-{}", std::process::id()));
        assert!(installed_clients_at(&base).is_empty());
        for client in [RobloxClient::Standard, RobloxClient::Vng] {
            let version = installation_root(&base, client).join("Versions/version-player");
            fs::create_dir_all(&version).unwrap();
            fs::write(version.join("RobloxPlayerBeta.exe"), b"fixture").unwrap();
            assert_eq!(
                find_player_for(&base, client).unwrap(),
                version.join("RobloxPlayerBeta.exe")
            );
        }
        assert_eq!(
            installed_clients_at(&base),
            vec![RobloxClient::Standard, RobloxClient::Vng]
        );
        fs::remove_dir_all(installation_root(&base, RobloxClient::Standard)).unwrap();
        assert_eq!(installed_clients_at(&base), vec![RobloxClient::Vng]);
        assert!(
            find_player_for(&base, RobloxClient::Standard)
                .unwrap_err()
                .contains("Use Change player")
        );
        let version =
            installation_root(&base, RobloxClient::Standard).join("Versions/version-player");
        fs::create_dir_all(&version).unwrap();
        fs::write(version.join("RobloxPlayerBeta.exe"), b"fixture").unwrap();
        fs::remove_dir_all(installation_root(&base, RobloxClient::Vng)).unwrap();
        assert_eq!(installed_clients_at(&base), vec![RobloxClient::Standard]);
        assert!(
            find_player_for(&base, RobloxClient::Vng)
                .unwrap_err()
                .contains("Use Change player")
        );
        assert!(find_player_for(&base, RobloxClient::Standard).is_ok());
        fs::remove_dir_all(base).unwrap();
    }
}
