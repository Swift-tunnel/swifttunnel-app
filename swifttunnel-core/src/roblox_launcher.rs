//! Bounded local launcher preferences.
use crate::roblox_library::valid_place_id;
use serde::{Deserialize, Serialize};
use std::{fs, io::Read, path::PathBuf};
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    #[default]
    Closest,
    FewerPlayers,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Matchmaker {
    pub enabled: bool,
    pub mode: MatchMode,
    pub blocked_datacenters: Vec<u32>,
    pub preferred_datacenter: Option<u32>,
    pub skipped_games: Vec<String>,
    pub minimum_free_slots: u32,
    pub search_limit: u32,
    pub prepare_tunnel: bool,
    pub offer_better_server: bool,
}
impl Default for Matchmaker {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: MatchMode::Closest,
            blocked_datacenters: vec![],
            preferred_datacenter: None,
            skipped_games: vec![],
            minimum_free_slots: 1,
            search_limit: 40,
            prepare_tunnel: true,
            offer_better_server: false,
        }
    }
}
impl Matchmaker {
    pub fn validate(&self) -> Result<(), String> {
        if self.blocked_datacenters.len() > 100
            || self.blocked_datacenters.contains(&0)
            || self.preferred_datacenter == Some(0)
            || self
                .preferred_datacenter
                .is_some_and(|id| self.blocked_datacenters.contains(&id))
            || self.skipped_games.len() > 50
            || self.skipped_games.iter().any(|id| !valid_place_id(id))
            || !(1..=20).contains(&self.minimum_free_slots)
            || !(10..=200).contains(&self.search_limit)
        {
            return Err("Choose valid Matchmaker locations, game IDs, 1 to 20 free slots and a search limit from 10 to 200.".into());
        }
        Ok(())
    }
    pub fn applies(&self, place: &str) -> bool {
        self.enabled && !self.skipped_games.iter().any(|id| id == place)
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LauncherConfig {
    pub matchmaker: Matchmaker,
    pub offer_recovery: bool,
}
impl LauncherConfig {
    pub fn validate(&self) -> Result<(), String> {
        self.matchmaker.validate()?;
        Ok(())
    }
    pub fn load() -> Result<Self, String> {
        let value: Self = load("launcher.json")?.unwrap_or_default();
        value.validate()?;
        Ok(value)
    }
    pub fn save(&self) -> Result<(), String> {
        self.validate()?;
        save("launcher.json", self)
    }
}
fn path(name: &str) -> Result<PathBuf, String> {
    if name != "launcher.json" {
        return Err("Unknown launcher data file.".into());
    }
    Ok(crate::roblox_library::library_path()?.with_file_name(name))
}
pub fn load<T: serde::de::DeserializeOwned>(name: &str) -> Result<Option<T>, String> {
    let path = path(name)?;
    crate::roblox_native_launch::safe_path(&path)?;
    let mut bytes = vec![];
    match fs::File::open(path) {
        Ok(f) => {
            f.take(256 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    }
    if bytes.len() > 256 * 1024 {
        return Err("Launcher data is too large; the original file was kept.".into());
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| "Launcher data could not be read; the original file was kept.".into())
}
pub fn save<T: Serialize>(name: &str, value: &T) -> Result<(), String> {
    let path = path(name)?;
    crate::roblox_native_launch::safe_path(&path)?;
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if bytes.len() > 256 * 1024 {
        return Err("Launcher data is too large to save.".into());
    }
    fs::create_dir_all(path.parent().ok_or("Invalid launcher settings path.")?)
        .map_err(|e| e.to_string())?;
    crate::atomic_file::replace(&path, &bytes).map_err(|e| e.to_string())
}
pub fn qualifies(server: &crate::roblox_directory::GameServer, minimum_free_slots: u32) -> bool {
    server.availability == crate::roblox_directory::Availability::Available
        && server
            .capacity
            .zip(server.playing)
            .is_some_and(|(cap, playing)| cap.saturating_sub(playing) >= minimum_free_slots)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn removed_profiles_cannot_block_current_launcher_settings() {
        let config: LauncherConfig = serde_json::from_str(
            r#"{
            "matchmaker":{"enabled":true},
            "profiles":[{"name":"Old", "settings":{"custom_fflags_enabled":true,
                "custom_fflags_json":"{\"FFlagDoesNotExist\":true}"}}]
        }"#,
        )
        .unwrap();
        assert!(config.matchmaker.enabled);
        assert!(config.validate().is_ok());
        assert!(
            serde_json::to_value(config)
                .unwrap()
                .get("profiles")
                .is_none()
        );
        let malformed: LauncherConfig =
            serde_json::from_str(r#"{"profiles":"retired data"}"#).unwrap();
        assert!(malformed.validate().is_ok());
    }
    #[test]
    fn matcher_never_uses_full_unknown_or_insufficient_servers() {
        use crate::roblox_directory::{Availability, GameServer};
        let mut s = GameServer {
            job_id: String::new(),
            datacenter_id: 1,
            ip: None,
            first_seen: String::new(),
            playing: Some(9),
            capacity: Some(10),
            availability: Availability::Available,
        };
        assert!(qualifies(&s, 1));
        assert!(!qualifies(&s, 2));
        s.availability = Availability::Unknown;
        assert!(!qualifies(&s, 1));
    }
    #[test]
    fn blocked_preference_and_unbounded_search_are_rejected() {
        let mut c = Matchmaker::default();
        c.preferred_datacenter = Some(8);
        c.blocked_datacenters = vec![8];
        assert!(c.validate().is_err());
        c.blocked_datacenters.clear();
        c.search_limit = 10000;
        assert!(c.validate().is_err());
    }
}
