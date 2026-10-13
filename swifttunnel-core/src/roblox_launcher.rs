//! Bounded local launcher preferences, named profiles and session reports.
use crate::{roblox_library::valid_place_id, structs::RobloxSettingsConfig};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
};
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedProfile {
    pub name: String,
    pub settings: RobloxSettingsConfig,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LauncherConfig {
    pub matchmaker: Matchmaker,
    pub profiles: Vec<NamedProfile>,
    pub offer_recovery: bool,
}
impl LauncherConfig {
    pub fn validate(&self) -> Result<(), String> {
        self.matchmaker.validate()?;
        if self.profiles.len() > 20 {
            return Err("Keep up to 20 named profiles.".into());
        }
        for (i, p) in self.profiles.iter().enumerate() {
            if !valid_profile_name(&p.name)
                || self.profiles[..i]
                    .iter()
                    .any(|old| old.name.eq_ignore_ascii_case(&p.name))
                || !(30..=99999).contains(&p.settings.target_fps)
                || p.settings.custom_fflags_json.len() > 8192
            {
                return Err("Profiles need unique names and valid frame-rate caps.".into());
            }
            crate::roblox_optimizer::RobloxOptimizer::native_launch_flags(&p.settings)
                .map_err(|e| e.to_string())?;
        }
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
pub fn valid_profile_name(name: &str) -> bool {
    !name.trim().is_empty()
        && name == name.trim()
        && name.len() <= 48
        && !name.chars().any(char::is_control)
}
fn path(name: &str) -> Result<PathBuf, String> {
    if !matches!(name, "launcher.json" | "game-sessions.json") {
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
    let temp = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|e| e.to_string())?;
    let result = (|| {
        f.write_all(&bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result.map_err(|e| e.to_string())
}
pub fn qualifies(server: &crate::roblox_directory::GameServer, minimum_free_slots: u32) -> bool {
    server.availability == crate::roblox_directory::Availability::Available
        && server
            .capacity
            .zip(server.playing)
            .is_some_and(|(cap, playing)| cap.saturating_sub(playing) >= minimum_free_slots)
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionReport {
    pub relay_probe_loss_pct: Option<f32>,
    pub relay_probe_variation_ms: Option<u32>,
    pub place_id: String,
    pub game_name: String,
    pub started_at: u64,
    pub duration_seconds: u64,
    pub location: Option<String>,
    pub samples: u32,
    pub average_fps: Option<u32>,
    pub low_fps: Option<u32>,
    pub average_network_ms: Option<u32>,
    pub network_variation_ms: Option<u32>,
    pub frame_spikes: u64,
    pub peak_frame_ms: Option<u32>,
    pub ended_without_leave: bool,
}
#[derive(Default)]
pub struct SessionRecorder {
    pub probe_received: u64,
    pub probe_samples: u32,
    pub previous_probe: Option<u32>,
    pub probe_variation: u64,
    pub report: SessionReport,
    pub fps_total: u64,
    pub fps_samples: u32,
    pub ping_total: u64,
    pub ping_samples: u32,
    pub last_ping: Option<u32>,
    pub ping_variation: u64,
}
impl SessionRecorder {
    pub fn sample_relay(&mut self, snapshot: Option<&crate::vpn::RelayPingSnapshot>) {
        let Some(snapshot) = snapshot.filter(|s| s.enabled && s.sample_count >= 3) else {
            return;
        };
        let Some(rtt) = snapshot.last_rtt_ms else {
            return;
        };
        if self.probe_received == snapshot.received {
            return;
        }
        self.probe_received = snapshot.received;
        self.probe_samples = self.probe_samples.saturating_add(1);
        if let Some(previous) = self.previous_probe {
            self.probe_variation += previous.abs_diff(rtt) as u64;
        }
        self.previous_probe = Some(rtt);
        if snapshot.loss_pct.is_finite() && (0.0..=100.0).contains(&snapshot.loss_pct) {
            self.report.relay_probe_loss_pct = Some(snapshot.loss_pct);
        }
    }
    pub fn sample(&mut self, fps: u32, ping: Option<u32>) {
        self.report.samples = self.report.samples.saturating_add(1);
        if fps > 0 {
            self.fps_total += fps as u64;
            self.fps_samples += 1;
            self.report.low_fps = Some(self.report.low_fps.map_or(fps, |old| old.min(fps)));
        }
        if let Some(ping) = ping.filter(|v| *v <= 4000) {
            self.ping_total += ping as u64;
            self.ping_samples += 1;
            if let Some(old) = self.last_ping {
                self.ping_variation += old.abs_diff(ping) as u64;
            }
            self.last_ping = Some(ping);
        }
    }
    pub fn finish(mut self, at: u64, unexpected: bool) -> SessionReport {
        self.report.relay_probe_variation_ms = (self.probe_samples > 1)
            .then(|| (self.probe_variation / (self.probe_samples - 1) as u64) as u32);
        self.report.duration_seconds = at.saturating_sub(self.report.started_at);
        self.report.ended_without_leave = unexpected;
        self.report.average_fps =
            (self.fps_samples > 0).then(|| (self.fps_total / self.fps_samples as u64) as u32);
        self.report.average_network_ms =
            (self.ping_samples > 0).then(|| (self.ping_total / self.ping_samples as u64) as u32);
        self.report.network_variation_ms = (self.ping_samples > 1)
            .then(|| (self.ping_variation / (self.ping_samples - 1) as u64) as u32);
        self.report
    }
}
pub fn save_report(report: SessionReport) -> Result<(), String> {
    let mut reports: Vec<SessionReport> = load("game-sessions.json")?.unwrap_or_default();
    reports.truncate(19);
    reports.insert(0, report);
    save("game-sessions.json", &reports)
}
#[cfg(test)]
mod tests {
    use super::*;
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
    #[test]
    fn missing_measurements_remain_unknown() {
        let r = SessionRecorder::default().finish(5, false);
        assert_eq!(r.average_network_ms, None);
        assert_eq!(r.average_fps, None);
    }
    #[test]
    fn old_config_loads_disabled_and_profiles_reject_ignored_flags() {
        let config: LauncherConfig = serde_json::from_str("{}").unwrap();
        assert!(!config.matchmaker.enabled);
        assert!(!config.offer_recovery);
        let mut invalid = LauncherConfig::default();
        let settings = RobloxSettingsConfig {
            custom_fflags_enabled: true,
            custom_fflags_json: r#"{"FFlagDoesNotExist":true}"#.into(),
            ..Default::default()
        };
        invalid.profiles.push(NamedProfile {
            name: "Test".into(),
            settings,
        });
        assert!(invalid.validate().is_err());
    }
    #[test]
    fn relay_variation_does_not_count_the_same_control_reply_twice() {
        use crate::vpn::RelayPingSnapshot;
        let mut r = SessionRecorder::default();
        let mut s = RelayPingSnapshot {
            enabled: true,
            sent: 4,
            received: 3,
            loss_pct: 0.0,
            last_rtt_ms: Some(20),
            p50_rtt_ms: Some(20),
            p99_rtt_ms: Some(20),
            sample_count: 3,
        };
        r.sample_relay(Some(&s));
        r.sample_relay(Some(&s));
        s.received = 4;
        s.last_rtt_ms = Some(24);
        r.sample_relay(Some(&s));
        let report = r.finish(5, false);
        assert_eq!(report.relay_probe_variation_ms, Some(4));
        assert_eq!(report.relay_probe_loss_pct, Some(0.0));
    }
    #[test]
    fn recovery_is_not_inferred_from_normal_leave_and_jitter_uses_deltas() {
        let mut r = SessionRecorder::default();
        r.sample(120, Some(20));
        r.sample(60, Some(30));
        r.sample(0, None);
        let report = r.finish(5, false);
        assert!(!report.ended_without_leave);
        assert_eq!(report.average_fps, Some(90));
        assert_eq!(report.network_variation_ms, Some(10));
    }
}
