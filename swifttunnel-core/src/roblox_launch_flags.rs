//! Temporary native-player flags. Other launchers' files are never changed.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};
#[derive(Serialize, Deserialize)]
struct Entry {
    path: PathBuf,
    before: Option<String>,
    applied: String,
}
#[derive(Serialize, Deserialize)]
struct Journal {
    entries: Vec<Entry>,
    flags: HashMap<String, String>,
}
const RESTORE_ERROR: &str =
    "Couldn't restore your Roblox FastFlags. Contact support and include your log.";
fn journal_path() -> Result<PathBuf, String> {
    Ok(crate::roblox_library::library_path()?.with_file_name("native-launch-flags.json"))
}
pub fn pending() -> bool {
    journal_path().is_ok_and(|p| p.exists())
}
fn read(path: &Path) -> Result<Option<String>, String> {
    crate::roblox_native_launch::safe_path(path)?;
    let mut bytes = Vec::new();
    let limit = if path
        .file_name()
        .is_some_and(|name| name == "native-launch-flags.json")
    {
        256 * 1024
    } else {
        128 * 1024
    };
    match fs::File::open(path) {
        Ok(file) => {
            file.take(limit as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    }
    if bytes.len() > limit {
        log::warn!(
            "FastFlags file exceeds read limit of {limit} bytes: {}",
            path.display()
        );
        return Err(
            "Couldn't read your Roblox FastFlags. Contact support and include your log.".into(),
        );
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|e| e.to_string())
}
fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    crate::roblox_native_launch::safe_path(path)?;
    fs::create_dir_all(path.parent().ok_or("Invalid flags path.")?).map_err(|e| e.to_string())?;
    crate::atomic_file::replace(path, bytes).map_err(|e| e.to_string())
}
fn hash(raw: &str) -> String {
    format!("{:x}", Sha256::digest(raw.as_bytes()))
}
fn allowed(path: &Path) -> bool {
    let Some(base) = std::env::var_os("LOCALAPPDATA") else {
        return false;
    };
    allowed_in(&PathBuf::from(base), path)
}
fn allowed_in(base: &Path, path: &Path) -> bool {
    [
        crate::roblox_library::RobloxClient::Standard,
        crate::roblox_library::RobloxClient::Vng,
    ]
    .into_iter()
    .any(|client| {
        let versions =
            crate::roblox_native_launch::installation_root(base, client).join("Versions");
        let Ok(relative) = path.strip_prefix(versions) else {
            return false;
        };
        let parts = relative.components().collect::<Vec<_>>();
        parts.len() == 3
            && parts[0]
                .as_os_str()
                .to_string_lossy()
                .starts_with("version-")
            && parts[1].as_os_str() == "ClientSettings"
            && parts[2].as_os_str() == "ClientAppSettings.json"
    })
}
pub fn prepare(player: &Path, flags: HashMap<String, String>) -> Result<(), String> {
    if !crate::roblox_game_profile::player_stopped() {
        return Err("Close Roblox before preparing launch flags.".into());
    }
    restore()?;
    let path = player
        .parent()
        .ok_or("Invalid Roblox installation.")?
        .join("ClientSettings/ClientAppSettings.json");
    if !allowed(&path) {
        return Err("SwiftTunnel only applies launch flags to the official player.".into());
    }
    let before = read(&path)?;
    if before.as_ref().is_some_and(|raw| raw.len() > 64 * 1024) {
        return Err(
            "The existing Roblox flags file is too large to back up safely. It was kept.".into(),
        );
    }
    let raw = serde_json::to_string_pretty(&flags).map_err(|e| e.to_string())?;
    let journal = Journal {
        entries: vec![Entry {
            path: path.clone(),
            before,
            applied: hash(&raw),
        }],
        flags,
    };
    write(
        &journal_path()?,
        &serde_json::to_vec(&journal).map_err(|e| e.to_string())?,
    )?;
    write(&path, raw.as_bytes())
}
pub fn restore() -> Result<bool, String> {
    if !pending() || !crate::roblox_game_profile::player_stopped() {
        return Ok(false);
    }
    let Some(raw) = read(&journal_path()?)? else {
        return Ok(false);
    };
    let journal: Journal = serde_json::from_str(&raw).map_err(|error| {
        log::warn!("Native FastFlags recovery record could not be decoded; retained for inspection: {error}");
        RESTORE_ERROR
    })?;
    if journal.entries.len() > 4
        || journal
            .entries
            .iter()
            .any(|e| !allowed(&e.path) || e.applied.len() != 64)
    {
        log::warn!(
            "Native FastFlags recovery record failed path or hash validation; retained for inspection"
        );
        return Err(RESTORE_ERROR.into());
    }
    for e in journal.entries {
        restore_entry(e)?;
    }
    fs::remove_file(journal_path()?).map_err(|e| e.to_string())?;
    Ok(true)
}
fn restore_entry(e: Entry) -> Result<(), String> {
    if read(&e.path)?
        .as_deref()
        .is_some_and(|raw| hash(raw) == e.applied)
    {
        match e.before {
            Some(before) => write(&e.path, before.as_bytes())?,
            None => fs::remove_file(e.path).map_err(|e| e.to_string())?,
        }
    }
    Ok(())
}
pub fn diagnostic() -> Result<Option<String>, String> {
    let Some(raw) = read(&journal_path()?)? else {
        return Ok(None);
    };
    let journal: Journal = serde_json::from_str(&raw).map_err(|error| {
        log::warn!("Native FastFlags recovery diagnostic could not decode record: {error}");
        RESTORE_ERROR
    })?;
    if journal.entries.len() > 4 || journal.entries.iter().any(|e| !allowed(&e.path)) {
        log::warn!("Native FastFlags recovery diagnostic rejected record paths");
        return Err(RESTORE_ERROR.into());
    }
    for entry in &journal.entries {
        if read(&entry.path)?
            .as_deref()
            .is_none_or(|raw| hash(raw) != entry.applied)
        {
            return Ok(Some("Something else changed Roblox's flags during this launch. Check whether another launcher is running.".into()));
        }
    }
    let client = if std::env::var_os("LOCALAPPDATA").is_some_and(|base| {
        journal.entries.first().is_some_and(|entry| {
            entry
                .path
                .starts_with(crate::roblox_native_launch::installation_root(
                    &PathBuf::from(base),
                    crate::roblox_library::RobloxClient::Vng,
                ))
        })
    }) {
        crate::roblox_library::RobloxClient::Vng
    } else {
        crate::roblox_library::RobloxClient::Standard
    };
    if !journal.flags.is_empty()
        && let Ok(player) = crate::roblox_native_launch::official_player_for(client)
        && journal
            .entries
            .iter()
            .all(|entry| player.parent() != entry.path.parent().and_then(Path::parent))
    {
        return Ok(Some(
            "Roblox updated during this launch. Press Play again to load your FastFlags.".into(),
        ));
    }
    Ok(None)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restoration_recovers_original_bytes_but_preserves_external_changes() {
        let root = std::env::temp_dir().join(format!("swift-flags-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("ClientAppSettings.json");
        let original = "{\"old\":true}";
        let applied = "{}";
        fs::write(&path, applied).unwrap();
        restore_entry(Entry {
            path: path.clone(),
            before: Some(original.into()),
            applied: hash(applied),
        })
        .unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        fs::write(&path, "external edit").unwrap();
        restore_entry(Entry {
            path: path.clone(),
            before: Some(original.into()),
            applied: hash(applied),
        })
        .unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "external edit");
        fs::write(&path, applied).unwrap();
        restore_entry(Entry {
            path: path.clone(),
            before: None,
            applied: hash(applied),
        })
        .unwrap();
        assert!(!path.exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn paths_cannot_escape_into_another_strap() {
        let root = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap());
        assert!(allowed(&root.join(
            "Roblox/Versions/version-test/ClientSettings/ClientAppSettings.json"
        )));
        assert!(allowed(&root.join(
            "RobloxPCVNG/Versions/version-test/ClientSettings/ClientAppSettings.json"
        )));
        assert!(!allowed(&root.join(
            "Voidstrap/Versions/version-test/ClientSettings/ClientAppSettings.json"
        )));
        assert!(!allowed(&root.join(
            "Roblox/Versions/version-test/../ClientSettings/ClientAppSettings.json"
        )));
        assert!(!allowed(&root.join(
            "RobloxPCVNG/Versions/version-test/../ClientSettings/ClientAppSettings.json"
        )));
        assert!(!allowed(&root.join(
            "RobloxPCVNG/Versions/version-test/ClientSettings/not-flags.json"
        )));
    }
}
