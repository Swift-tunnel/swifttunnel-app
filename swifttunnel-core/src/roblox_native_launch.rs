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
fn find_player_for(base: &Path, client: RobloxClient) -> Result<PathBuf, String> {
    find_player(&installation_root(base, client).join("Versions")).map_err(|_| match client {
        RobloxClient::Standard => "Install Roblox from roblox.com first.".into(),
        RobloxClient::Vng => "Install Roblox VNG from robloxapp.vnggames.com first.".into(),
    })
}
pub fn updater_running() -> bool {
    let Some(root) = std::env::var_os("LOCALAPPDATA") else {
        return false;
    };
    let roots = [RobloxClient::Standard, RobloxClient::Vng]
        .map(|client| installation_root(&PathBuf::from(&root), client));
    #[cfg(windows)]
    {
        let Ok(processes) = crate::process_snapshot::list() else {
            return false;
        };
        processes
            .iter()
            .filter(|process| is_updater_name(&process.name))
            .any(|process| {
                crate::process_snapshot::image_path(process.pid)
                    .ok()
                    .flatten()
                    .is_some_and(|image| {
                        roots.iter().any(|root| Path::new(&image).starts_with(root))
                    })
            })
    }
    #[cfg(not(windows))]
    {
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
fn is_updater_name(name: &str) -> bool {
    [
        "RobloxPlayerInstaller.exe",
        "RobloxInstaller.exe",
        "RobloxPlayerLauncher.exe",
    ]
    .iter()
    .any(|expected| name.eq_ignore_ascii_case(expected))
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
    let image = image
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    [RobloxClient::Standard, RobloxClient::Vng]
        .into_iter()
        .find(|client| {
            let root = installation_root(base, *client)
                .to_string_lossy()
                .replace('/', "\\")
                .to_ascii_lowercase();
            image.starts_with(&format!("{}\\", root.trim_end_matches('\\')))
        })
}

pub fn running_client() -> Result<Option<RobloxClient>, String> {
    #[cfg(windows)]
    {
        let base = std::env::var_os("LOCALAPPDATA")
            .ok_or("Windows could not find the Roblox installation.")?;
        for process in crate::process_snapshot::list()? {
            if crate::process_names::is_roblox_player_process_name(&process.name)
                && let Some(image) = crate::process_snapshot::image_path(process.pid)?
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
        for client in [RobloxClient::Standard, RobloxClient::Vng] {
            let version = installation_root(&base, client).join("Versions/version-player");
            fs::create_dir_all(&version).unwrap();
            fs::write(version.join("RobloxPlayerBeta.exe"), b"fixture").unwrap();
            assert_eq!(
                find_player_for(&base, client).unwrap(),
                version.join("RobloxPlayerBeta.exe")
            );
        }
        fs::remove_dir_all(installation_root(&base, RobloxClient::Vng)).unwrap();
        assert!(
            find_player_for(&base, RobloxClient::Vng)
                .unwrap_err()
                .contains("Install Roblox VNG")
        );
        assert!(find_player_for(&base, RobloxClient::Standard).is_ok());
        fs::remove_dir_all(base).unwrap();
    }
}
