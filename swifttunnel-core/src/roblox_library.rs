//! Small local game library. No account cookies, join tickets or server IPs.
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_ENTRIES: usize = 50;
const MAX_FAVOURITES: usize = 20;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RobloxClient {
    #[default]
    Standard,
    Vng,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GameEntry {
    pub place_id: String,
    pub name: String,
    pub job_id: Option<String>,
    pub last_played: Option<u64>,
    pub favourite: bool,
    #[serde(default)]
    pub client: RobloxClient,
    #[serde(default)]
    pub preferences: GamePreferences,
    #[serde(default)]
    pub icon_url: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GamePreferences {
    pub datacenter_id: Option<u32>,
    pub fps_cap: Option<u32>,
    pub graphics_quality: Option<crate::structs::GraphicsQuality>,
    pub use_tunnel: bool,
    pub skip_matchmaker: bool,
    pub borderless: bool,
    pub monitor: Option<String>,
}
impl GamePreferences {
    pub fn validate(&self) -> Result<(), String> {
        if self
            .monitor
            .as_ref()
            .is_some_and(|name| name.len() > 128 || name.chars().any(char::is_control))
            || self.datacenter_id == Some(0)
            || self.fps_cap.is_some_and(|fps| !(30..=99999).contains(&fps))
        {
            return Err("Choose a valid datacenter and a frame-rate cap from 30 to 99999.".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod retired_preference_tests {
    use super::*;
    #[test]
    fn an_obsolete_profile_name_cannot_block_saving_current_preferences() {
        let preferences: GamePreferences =
            serde_json::from_str(r#"{"flag_profile":"invalid\nold profile","fps_cap":240}"#)
                .unwrap();
        assert!(preferences.validate().is_ok());
        assert_eq!(preferences.fps_cap, Some(240));
        assert!(
            serde_json::to_value(preferences)
                .unwrap()
                .get("flag_profile")
                .is_none()
        );
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GameLibrary {
    pub entries: Vec<GameEntry>,
    pub notify_joins: bool,
}

pub fn valid_place_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 19
        && id.bytes().all(|b| b.is_ascii_digit())
        && !id.starts_with('0')
        && id.parse::<u64>().is_ok_and(|n| n <= i64::MAX as u64)
}

pub fn valid_job_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
        && id.bytes().any(|b| b != b'0' && b != b'-')
}

pub fn library_path() -> Result<PathBuf, String> {
    dirs::config_dir()
        .map(|p| p.join("SwiftTunnel").join("games.json"))
        .ok_or_else(|| "Windows could not find your settings folder.".into())
}

impl GameLibrary {
    pub fn load(path: &Path) -> Result<Self, String> {
        match fs::metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(format!("Could not read your game library: {e}")),
            Ok(meta) if meta.len() > 128 * 1024 => {
                return Err("Your game library is too large to read safely.".into());
            }
            _ => {}
        }
        let mut bytes = Vec::new();
        fs::File::open(path)
            .and_then(|file| file.take(128 * 1024 + 1).read_to_end(&mut bytes))
            .map_err(|e| format!("Could not read your game library: {e}"))?;
        if bytes.len() > 128 * 1024 {
            return Err("Your game library is too large to read safely.".into());
        }
        let library: Self = serde_json::from_slice(&bytes).map_err(|_| {
            "Your game library could not be read. The original file has been kept.".to_string()
        })?;
        if library.entries.len() > MAX_ENTRIES
            || library.entries.iter().filter(|e| e.favourite).count() > MAX_FAVOURITES
            || library.entries.iter().any(|entry| {
                !valid_place_id(&entry.place_id)
                    || entry.preferences.validate().is_err()
                    || entry
                        .icon_url
                        .as_deref()
                        .is_some_and(|url| !valid_icon_url(url))
                    || entry.name.len() > 400
                    || entry.name.chars().any(char::is_control)
                    || entry.job_id.as_deref().is_some_and(|id| !valid_job_id(id))
            })
            || library.entries.iter().enumerate().any(|(i, e)| {
                library.entries[..i]
                    .iter()
                    .any(|other| other.place_id == e.place_id && other.client == e.client)
            })
        {
            return Err(
                "Your game library contains invalid entries. The original file has been kept."
                    .into(),
            );
        }
        Ok(library)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let parent = path.parent().ok_or("Invalid game-library location.")?;
        fs::create_dir_all(parent).map_err(|e| format!("Could not save your game library: {e}"))?;
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
        let mut created = false;
        let result = (|| -> std::io::Result<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            created = true;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, path)
        })();
        // Only remove a file we created; an existing temporary file belongs to
        // another operation or is recoverable data from an interrupted save.
        if result.is_err() && created {
            let _ = fs::remove_file(&temporary);
        }
        result.map_err(|e| format!("Could not save your game library: {e}"))
    }

    pub fn record_join(
        &mut self,
        place_id: &str,
        job_id: &str,
        client: RobloxClient,
        at: u64,
    ) -> Result<(), String> {
        if !valid_place_id(place_id) || !valid_job_id(job_id) {
            return Err("Invalid Roblox game or server ID.".into());
        }
        let index = self.ensure_entry(place_id, client)?;
        self.entries[index].job_id = Some(job_id.to_ascii_lowercase());
        self.entries[index].last_played = Some(at);
        self.sort();
        Ok(())
    }

    fn ensure_entry(&mut self, place_id: &str, client: RobloxClient) -> Result<usize, String> {
        if !valid_place_id(place_id) {
            return Err("Enter a valid Roblox place ID.".into());
        }
        if let Some(i) = self
            .entries
            .iter()
            .position(|e| e.place_id == place_id && e.client == client)
        {
            return Ok(i);
        }
        if self.entries.len() >= MAX_ENTRIES {
            let oldest = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| !e.favourite)
                .min_by_key(|(_, e)| e.last_played)
                .map(|(i, _)| i)
                .ok_or("Your game library is full.")?;
            self.entries.remove(oldest);
        }
        self.entries.push(GameEntry {
            place_id: place_id.into(),
            name: format!("Place {place_id}"),
            job_id: None,
            last_played: None,
            favourite: false,
            client,
            preferences: GamePreferences::default(),
            icon_url: None,
        });
        Ok(self.entries.len() - 1)
    }

    pub fn set_favourite(
        &mut self,
        place_id: &str,
        client: RobloxClient,
        favourite: bool,
    ) -> Result<(), String> {
        if favourite
            && self.entries.iter().filter(|e| e.favourite).count() >= MAX_FAVOURITES
            && !self
                .entries
                .iter()
                .any(|e| e.place_id == place_id && e.client == client && e.favourite)
        {
            return Err("You can save up to 20 favourites. Remove one first.".into());
        }
        let index = self.ensure_entry(place_id, client)?;
        self.entries[index].favourite = favourite;
        Ok(())
    }

    pub fn set_name(&mut self, place_id: &str, client: RobloxClient, name: &str) {
        let name = name.trim();
        if !name.is_empty()
            && name.len() <= 400
            && !name.chars().any(char::is_control)
            && let Some(entry) = self
                .entries
                .iter_mut()
                .find(|e| e.place_id == place_id && e.client == client)
        {
            entry.name = name.into();
        }
    }

    pub fn set_icon(&mut self, place_id: &str, client: RobloxClient, icon: &str) {
        if valid_icon_url(icon)
            && let Some(entry) = self
                .entries
                .iter_mut()
                .find(|e| e.place_id == place_id && e.client == client)
        {
            entry.icon_url = Some(icon.into());
        }
    }
    pub fn set_preferences(
        &mut self,
        place_id: &str,
        client: RobloxClient,
        preferences: GamePreferences,
    ) -> Result<(), String> {
        preferences.validate()?;
        let index = self.ensure_entry(place_id, client)?;
        self.entries[index].preferences = preferences;
        Ok(())
    }

    pub fn forget(&mut self, place_id: &str, client: RobloxClient) {
        self.entries
            .retain(|e| e.place_id != place_id || e.client != client);
    }

    fn sort(&mut self) {
        self.entries
            .sort_by(|a, b| b.last_played.cmp(&a.last_played));
    }
}

pub fn valid_icon_url(value: &str) -> bool {
    if value.len() > 512 {
        return false;
    }
    url::Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.port().is_none()
            && url
                .host_str()
                .is_some_and(|host| host == "rbxcdn.com" || host.ends_with(".rbxcdn.com"))
    })
}

/// Build only known Roblox URLs from validated identifiers. Never pass user
/// input to a command shell or accept private-server access tokens here.
pub fn join_url(
    place_id: &str,
    job_id: Option<&str>,
    _client: RobloxClient,
) -> Result<String, String> {
    if !valid_place_id(place_id) || job_id.is_some_and(|id| !valid_job_id(id)) {
        return Err("Invalid Roblox game or server ID.".into());
    }
    // Both installed players accept Roblox deep links. The executable selected
    // by native launch determines the client; do not use the Windows URI handler.
    let mut url = format!("roblox://experiences/start?placeId={place_id}");
    if let Some(job) = job_id {
        url.push_str(&format!("&gameInstanceId={job}"));
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preferences_reject_bad_frame_caps_and_icons_cannot_point_at_local_files() {
        let mut lib = GameLibrary::default();
        assert!(
            lib.set_preferences(
                "1818",
                RobloxClient::Standard,
                GamePreferences {
                    fps_cap: Some(1),
                    ..Default::default()
                }
            )
            .is_err()
        );
        assert!(!valid_icon_url("file:///C:/Users/private.png"));
        assert!(!valid_icon_url("https://rbxcdn.com.evil/image.png"));
        assert!(valid_icon_url("https://tr.rbxcdn.com/image.png"));
    }
    const JOB: &str = "550e8400-e29b-41d4-a716-446655440000";
    #[test]
    fn favourite_changes_keep_cards_in_place_and_recent_order_survives_new_joins() {
        let mut lib = GameLibrary::default();
        lib.record_join("1818", JOB, RobloxClient::Standard, 10)
            .unwrap();
        lib.record_join("1819", JOB, RobloxClient::Standard, 20)
            .unwrap();
        let order = lib
            .entries
            .iter()
            .map(|e| e.place_id.clone())
            .collect::<Vec<_>>();
        for favourite in [true, false, true] {
            lib.set_favourite("1818", RobloxClient::Standard, favourite)
                .unwrap();
            assert_eq!(
                lib.entries
                    .iter()
                    .map(|e| e.place_id.clone())
                    .collect::<Vec<_>>(),
                order
            );
        }
        lib.record_join("1820", JOB, RobloxClient::Standard, 30)
            .unwrap();
        assert_eq!(lib.entries[0].place_id, "1820");
    }
    #[test]
    fn joins_update_one_entry_and_preserve_favourites() {
        let mut lib = GameLibrary::default();
        lib.set_favourite("1818", RobloxClient::Standard, true)
            .unwrap();
        lib.record_join("1818", JOB, RobloxClient::Standard, 10)
            .unwrap();
        lib.record_join("1818", JOB, RobloxClient::Standard, 20)
            .unwrap();
        assert_eq!(lib.entries.len(), 1);
        assert!(lib.entries[0].favourite);
        assert_eq!(lib.entries[0].last_played, Some(20));
    }
    #[test]
    fn histories_are_bounded_and_keep_favourites() {
        let mut lib = GameLibrary::default();
        lib.set_favourite("1818", RobloxClient::Standard, true)
            .unwrap();
        for id in 1..100 {
            lib.record_join(&id.to_string(), JOB, RobloxClient::Standard, id)
                .unwrap();
        }
        assert_eq!(lib.entries.len(), 50);
        assert!(lib.entries.iter().any(|e| e.place_id == "1818"));
        assert!(!lib.entries.iter().any(|e| e.place_id == "1"));
    }
    #[test]
    fn hostile_identifiers_cannot_become_launch_commands() {
        for id in [
            "0",
            "1&accessCode=secret",
            "1\";calc",
            "9223372036854775808",
        ] {
            assert!(join_url(id, None, RobloxClient::Standard).is_err());
        }
        assert!(join_url("1818", Some("x&userId=1"), RobloxClient::Standard).is_err());
        assert_eq!(
            join_url("1818", Some(JOB), RobloxClient::Standard).unwrap(),
            format!("roblox://experiences/start?placeId=1818&gameInstanceId={JOB}")
        );
        assert_eq!(
            join_url("1818", Some(JOB), RobloxClient::Vng).unwrap(),
            join_url("1818", Some(JOB), RobloxClient::Standard).unwrap()
        );
        assert!(join_url("1818", Some("x&ticket=secret"), RobloxClient::Vng).is_err());
    }
    #[test]
    fn damaged_library_is_never_silently_replaced() {
        let path =
            std::env::temp_dir().join(format!("swift-library-test-{}.json", std::process::id()));
        fs::write(&path, b"broken").unwrap();
        assert!(GameLibrary::load(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"broken");
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn saved_library_round_trips_without_server_addresses_or_tokens() {
        let path = std::env::temp_dir().join(format!(
            "swift-library-roundtrip-{}.json",
            std::process::id()
        ));
        let mut lib = GameLibrary::default();
        lib.record_join("1818", JOB, RobloxClient::Standard, 20)
            .unwrap();
        lib.save(&path).unwrap();
        lib.set_favourite("1818", RobloxClient::Standard, true)
            .unwrap();
        lib.save(&path).unwrap();
        assert_eq!(GameLibrary::load(&path).unwrap().entries, lib.entries);
        fs::remove_file(path).unwrap();
    }
}
