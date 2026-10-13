use crate::state::AppState;
use serde::Serialize;
use swifttunnel_core::roblox_library::{
    GameEntry, GameLibrary, RobloxClient, join_url, library_path,
};
use tauri::{Emitter, State};

pub const LIBRARY_CHANGED: &str = "roblox-library-changed";

#[tauri::command]
pub async fn games_nvidia_profile()
-> Result<swifttunnel_core::nvidia_profile::DriverProfile, String> {
    tauri::async_runtime::spawn_blocking(swifttunnel_core::nvidia_profile::inspect)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn games_save_nvidia(
    state: State<'_, AppState>,
    changes: Vec<swifttunnel_core::nvidia_profile::DriverChange>,
    expected: Vec<swifttunnel_core::nvidia_profile::DriverSetting>,
) -> Result<swifttunnel_core::nvidia_profile::DriverProfile, String> {
    let optimizer = state.roblox_optimizer.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let optimizer = optimizer.lock();
        if optimizer.is_roblox_running() {
            return Err("Close Roblox before changing its NVIDIA profile.".into());
        }
        swifttunnel_core::nvidia_profile::apply(changes, expected)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn games_save_flags(
    state: State<'_, AppState>,
    enabled: bool,
    json: String,
    expected_json: String,
    expected_enabled: bool,
    expected_ultraboost: bool,
) -> Result<crate::commands::optimizer::BoostUpdateResult, String> {
    if json.len() > 8192 {
        return Err("FastFlags must be under 8 KB.".into());
    }
    let optimizer = state.roblox_optimizer.clone();
    let settings = state.settings.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let optimizer = optimizer.lock();
        if swifttunnel_core::roblox_game_profile::pending() || swifttunnel_core::roblox_launch_flags::pending() {
            return Err("Close Roblox first, then apply FastFlags.".into());
        }
        let mut settings = settings.lock();
        let previous = &settings.config.roblox_settings;
        if previous.custom_fflags_json != expected_json
            || previous.custom_fflags_enabled != expected_enabled
            || previous.ultraboost != expected_ultraboost
        {
            return Err("FastFlags changed in another view. Reload the saved overrides before applying.".into());
        }
        let mut config = settings.config.clone();
        config.roblox_settings.custom_fflags_enabled = enabled;
        config.roblox_settings.custom_fflags_json = json;
        config.roblox_settings.ultraboost = false;
        let warnings = optimizer.apply_flag_overrides(&config.roblox_settings).map_err(|e| format!("Could not apply FastFlags: {e}. Some files may already be changed; review and retry."))?;
        let previous_config = settings.config.clone();
        settings.config = config.clone();
        if let Err(error) = swifttunnel_core::settings::save_settings(&settings) {
            settings.config = previous_config;
            return Err(format!("Flags were applied, but saving the configuration failed: {error}. Retry Save before closing."));
        }
        Ok(crate::commands::optimizer::BoostUpdateResult { warnings, applied_config: config })
    }).await.map_err(|e| e.to_string())?
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagAction {
    Preview,
    Clean,
    Undo,
}
#[tauri::command]
pub async fn games_flags(
    state: State<'_, AppState>,
    action: FlagAction,
) -> Result<swifttunnel_core::roblox_flag_cleanup::FlagCleanupReport, String> {
    let optimizer = state.roblox_optimizer.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = optimizer.lock();
        if !matches!(action, FlagAction::Preview)
            && (swifttunnel_core::roblox_game_profile::pending()
                || swifttunnel_core::roblox_launch_flags::pending())
        {
            return Err("Close Roblox first, then try again.".into());
        }
        match action {
            FlagAction::Preview => swifttunnel_core::roblox_flag_cleanup::preview(),
            FlagAction::Clean => swifttunnel_core::roblox_flag_cleanup::clean(),
            FlagAction::Undo => swifttunnel_core::roblox_flag_cleanup::undo(),
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn games_refresh_metadata(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let targets: Vec<_> = state
        .games
        .lock()
        .library()?
        .entries
        .iter()
        .filter(|e| e.icon_url.is_none())
        .take(6)
        .map(|e| (e.place_id.clone(), e.client))
        .collect();
    for (place, client) in targets {
        let _ = refresh_name(&state, &place, client).await;
    }
    let _ = app.emit(LIBRARY_CHANGED, ());
    Ok(())
}

#[tauri::command]
pub async fn games_scan_imports(
    state: State<'_, AppState>,
) -> Result<swifttunnel_core::roblox_optimizer::RobloxImportPreview, String> {
    let optimizer = state.roblox_optimizer.clone();
    tauri::async_runtime::spawn_blocking(move || {
        optimizer
            .lock()
            .inspect_launcher_imports()
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Could not scan launcher settings: {e}"))?
}

#[tauri::command]
pub async fn games_cleanup(
    state: State<'_, AppState>,
    kind: swifttunnel_core::roblox_cleanup::CleanupKind,
    delete: bool,
) -> Result<swifttunnel_core::roblox_cleanup::CleanupReport, String> {
    let monitor = state.performance_monitor.clone();
    tauri::async_runtime::spawn_blocking(move || {
        if delete && monitor.lock().is_roblox_running() {
            return Err("Close Roblox before cleaning its files, then try again.".into());
        }
        swifttunnel_core::roblox_cleanup::inspect(kind, delete)
    })
    .await
    .map_err(|e| format!("Could not complete cleanup: {e}"))?
}

#[derive(Clone, Serialize)]
pub struct CurrentGame {
    pub place_id: String,
    pub job_id: String,
    pub ip: String,
    pub client: RobloxClient,
    pub fresh_join: bool,
    pub observed_at: u64,
    pub location: Option<String>,
    pub location_source: Option<String>,
}

#[derive(Default)]
pub struct GamesState {
    pub previews: Vec<swifttunnel_core::vpn::route_preview::ReferenceEstimate>,
    pub recorder: Option<swifttunnel_core::roblox_launcher::SessionRecorder>,
    pub recovery: Option<CurrentGame>,
    pub recovery_shown: Vec<std::time::Instant>,
    pub process_gone_since: Option<std::time::Instant>,
    pub library: Option<GameLibrary>,
    pub current: Option<CurrentGame>,
    pub warning: Option<String>,
    pub status: Option<String>,
    pub search: Option<ServerSearch>,
    pub launch_started: Option<std::time::Instant>,
    pub launch_player_seen: bool,
    pub launch_updating: bool,
    pub launch_gone_since: Option<std::time::Instant>,
    pub owned_connection: Option<std::time::Instant>,
    pub cleanup_scheduled: bool,
    pub last_cleanup: Option<std::time::Instant>,
    pub idle_since: Option<std::time::Instant>,
    pub left_confirmed: bool,
    pub game_traffic_seen: bool,
}

pub struct ServerSearch {
    pub place_id: String,
    pub center: swifttunnel_core::roblox_directory::Datacenter,
    pub servers: Vec<swifttunnel_core::roblox_directory::GameServer>,
    pub fetched: std::time::Instant,
}

#[derive(Serialize)]
pub struct LibrarySnapshot {
    pub recovery: Option<CurrentGame>,
    pub entries: Vec<GameEntry>,
    pub current: Option<CurrentGame>,
    pub warning: Option<String>,
    pub status: Option<String>,
    pub notify_joins: bool,
    pub launch_pending: bool,
}

impl GamesState {
    pub fn launch_pending(&self) -> bool {
        self.launch_started.is_some() && (!self.launch_player_seen || self.launch_updating)
    }

    pub fn clear_launch(&mut self) {
        self.launch_started = None;
        self.launch_player_seen = false;
        self.launch_updating = false;
        self.launch_gone_since = None;
        self.status = None;
    }

    pub fn player_opened(&mut self) -> bool {
        if self.launch_started.is_none() || self.launch_player_seen && !self.launch_updating {
            return false;
        }
        self.launch_player_seen = true;
        self.launch_updating = false;
        self.launch_gone_since = None;
        self.warning = None;
        self.status = Some("Roblox is open.".into());
        log::info!("Roblox launch: player opened; waiting for confirmed game metadata");
        true
    }

    pub fn track_launch(&mut self, now: std::time::Instant, running: bool, updating: bool) -> bool {
        let Some(started) = self.launch_started else {
            return false;
        };
        if running {
            self.launch_gone_since = None;
            return self.player_opened();
        }
        if updating {
            self.launch_gone_since = None;
            let message = "Roblox is updating. The game opens when it is done.";
            if self.launch_updating {
                return false;
            }
            self.launch_updating = true;
            self.status = Some(message.into());
            return true;
        }
        if self.launch_player_seen {
            let gone = self.launch_gone_since.get_or_insert(now);
            if now.saturating_duration_since(*gone) < std::time::Duration::from_secs(3) {
                return false;
            }
            self.clear_launch();
            self.warning = None;
            self.left_confirmed = true;
            log::info!("Roblox launch: player closed before game metadata was confirmed");
            return true;
        }
        if now.saturating_duration_since(started) > std::time::Duration::from_secs(60) {
            self.clear_launch();
            self.left_confirmed = true;
            self.warning = Some("Roblox did not open within a minute. Try Play again.".into());
            log::warn!("Roblox launch: no player or active updater was observed before timeout");
            return true;
        }
        false
    }

    pub(super) fn library(&mut self) -> Result<&GameLibrary, String> {
        if self.library.is_none() {
            self.library = Some(GameLibrary::load(&library_path()?)?);
        }
        Ok(self.library.as_ref().unwrap())
    }

    pub fn mutate(
        &mut self,
        change: impl FnOnce(&mut GameLibrary) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut next = self.library()?.clone();
        change(&mut next)?;
        next.save(&library_path()?)?;
        self.library = Some(next);
        self.warning = None;
        Ok(())
    }

    pub fn record_join(&mut self, current: CurrentGame) {
        self.status = None;
        if self
            .current
            .as_ref()
            .is_none_or(|old| old.job_id != current.job_id)
        {
            if let Some(recorder) = self.recorder.take() {
                let _ = swifttunnel_core::roblox_launcher::save_report(
                    recorder.finish(chrono::Utc::now().timestamp().max(0) as u64, false),
                );
            }
            self.recorder = Some(swifttunnel_core::roblox_launcher::SessionRecorder {
                report: swifttunnel_core::roblox_launcher::SessionReport {
                    place_id: current.place_id.clone(),
                    game_name: self
                        .library()
                        .ok()
                        .and_then(|lib| {
                            lib.entries
                                .iter()
                                .find(|e| e.place_id == current.place_id)
                                .map(|e| e.name.clone())
                        })
                        .unwrap_or_else(|| format!("Place {}", current.place_id)),
                    started_at: chrono::Utc::now().timestamp().max(0) as u64,
                    ..Default::default()
                },
                ..Default::default()
            });
        }
        let at = chrono::Utc::now().timestamp().max(0) as u64;
        if let Err(error) = self
            .mutate(|lib| lib.record_join(&current.place_id, &current.job_id, current.client, at))
        {
            log::warn!("Game library: {error}");
            self.warning = Some(error);
        }
        self.current = Some(current);
    }
}

#[tauri::command]
pub fn games_get_library(state: State<'_, AppState>) -> Result<LibrarySnapshot, String> {
    let mut games = state.games.lock();
    let library = games.library()?.clone();
    Ok(LibrarySnapshot {
        entries: library.entries,
        notify_joins: library.notify_joins,
        current: games.current.clone(),
        warning: games.warning.clone(),
        status: games.status.clone(),
        launch_pending: games.launch_pending(),
        recovery: games.recovery.clone(),
    })
}
#[tauri::command]
pub fn games_dismiss_recovery(state: State<'_, AppState>) -> Result<(), String> {
    state.games.lock().recovery = None;
    Ok(())
}

#[tauri::command]
pub fn games_set_notifications(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    state.games.lock().mutate(|lib| {
        lib.notify_joins = enabled;
        Ok(())
    })
}

#[tauri::command]
pub fn games_set_favourite(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    place_id: String,
    client: RobloxClient,
    favourite: bool,
) -> Result<(), String> {
    {
        let mut games = state.games.lock();
        let warning = games.warning.clone();
        games.mutate(|lib| lib.set_favourite(&place_id, client, favourite))?;
        games.warning = warning;
    }
    let _ = app.emit(LIBRARY_CHANGED, ());
    Ok(())
}

#[tauri::command]
pub fn games_forget(
    state: State<'_, AppState>,
    place_id: String,
    client: RobloxClient,
) -> Result<(), String> {
    state.games.lock().mutate(|lib| {
        lib.forget(&place_id, client);
        Ok(())
    })
}

#[tauri::command]
pub fn games_join(
    place_id: String,
    job_id: Option<String>,
    client: RobloxClient,
) -> Result<(), String> {
    let url = join_url(&place_id, job_id.as_deref(), client)?;
    launch_url(&url)
}

#[cfg(windows)]
pub(super) fn launch_url(url: &str) -> Result<(), String> {
    // No command shell, arbitrary executable path, account cookie, or auth
    // ticket. Windows invokes the player's registered Roblox handler.
    use windows::{
        Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL},
        core::PCWSTR,
    };
    let wide: Vec<u16> = url.encode_utf16().chain(Some(0)).collect();
    let verb: Vec<u16> = "open".encode_utf16().chain(Some(0)).collect();
    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(wide.as_ptr()),
            None,
            None,
            SW_SHOWNORMAL,
        )
    };
    match result.0 as isize {
        code if code > 32 => Ok(()),
        31 => Err("Windows has no Roblox launcher registered. Install Roblox or choose your launcher as the default, then try again.".into()),
        code => Err(format!("Windows could not open Roblox (error {code}). Check your Roblox installation and default launcher.")),
    }
}

#[cfg(not(windows))]
pub(super) fn launch_url(_: &str) -> Result<(), String> {
    Err("Game launching is available on Windows.".into())
}

/// Resolve a display name through public Roblox endpoints. Failure leaves the
/// numeric place label; it never prevents a join or asks for a Roblox cookie.
pub async fn refresh_name(
    state: &AppState,
    place_id: &str,
    client: RobloxClient,
) -> Result<bool, String> {
    static METADATA_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
    let Ok(_slot) = METADATA_SLOTS.try_acquire() else {
        return Ok(false);
    };
    let needs_name = state.games.lock().library()?.entries.iter().any(|e| {
        e.place_id == place_id
            && e.client == client
            && (e.name == format!("Place {place_id}") || e.icon_url.is_none())
    });
    if !needs_name {
        return Ok(false);
    }
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let response = http
        .get(format!(
            "https://apis.roblox.com/universes/v1/places/{place_id}/universe"
        ))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?;
    let bytes = swifttunnel_core::http_body::read_bounded(response, 64 * 1024, "game name").await?;
    let data: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let universe = data
        .get("universeId")
        .and_then(|id| id.as_u64())
        .ok_or("Game name is unavailable.")?;
    let response = http
        .get(format!(
            "https://games.roblox.com/v1/games?universeIds={universe}"
        ))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?;
    let bytes = swifttunnel_core::http_body::read_bounded(response, 64 * 1024, "game name").await?;
    let data: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let name = data
        .get("data")
        .and_then(|d| d.get(0))
        .and_then(|d| d.get("name"))
        .and_then(|n| n.as_str())
        .ok_or("Game name is unavailable.")?;
    let icon = async {
        let response = http.get(format!("https://thumbnails.roblox.com/v1/games/icons?universeIds={universe}&size=256x256&format=Png&isCircular=false"))
            .send().await.ok()?.error_for_status().ok()?;
        let bytes = swifttunnel_core::http_body::read_bounded(response, 32 * 1024, "game icon").await.ok()?;
        let data: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        data.get("data")?.get(0)?.get("imageUrl")?.as_str().map(str::to_string)
    }.await;
    state.games.lock().mutate(|lib| {
        lib.set_name(place_id, client, name);
        if let Some(icon) = icon {
            lib.set_icon(place_id, client, &icon);
        }
        Ok(())
    })?;
    Ok(true)
}

#[tauri::command]
pub async fn games_add_favourite(
    state: State<'_, AppState>,
    place_id: String,
) -> Result<(), String> {
    state
        .games
        .lock()
        .mutate(|lib| lib.set_favourite(&place_id, RobloxClient::Standard, true))?;
    // The favourite is safely saved even when Roblox's metadata is unavailable.
    let _ = refresh_name(&state, &place_id, RobloxClient::Standard).await;
    Ok(())
}

#[cfg(test)]
mod launch_activity_tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn launch(at: Instant) -> GamesState {
        GamesState {
            launch_started: Some(at),
            status: Some("Roblox is opening.".into()),
            ..Default::default()
        }
    }

    #[test]
    fn opening_and_closing_without_metadata_cannot_later_become_a_failed_launch() {
        let at = Instant::now();
        let mut games = launch(at);
        assert!(games.launch_pending());
        assert!(games.track_launch(at + Duration::from_secs(2), true, false));
        assert!(!games.launch_pending());
        assert_eq!(games.status.as_deref(), Some("Roblox is open."));
        assert!(!games.track_launch(at + Duration::from_secs(14), false, false));
        assert!(games.track_launch(at + Duration::from_secs(17), false, false));
        assert!(games.launch_started.is_none());
        assert!(games.status.is_none());
        assert!(games.warning.is_none());
        assert!(games.left_confirmed);
        assert!(!games.track_launch(at + Duration::from_secs(65), false, false));
        assert!(games.warning.is_none());
    }

    #[test]
    fn a_fresh_open_log_covers_a_player_that_closed_between_process_polls() {
        let at = Instant::now();
        let mut games = launch(at);
        assert!(games.player_opened());
        assert!(!games.track_launch(at + Duration::from_secs(1), false, false));
        assert!(games.track_launch(at + Duration::from_secs(4), false, false));
        assert!(games.warning.is_none());
        assert!(!games.launch_pending());
    }

    #[test]
    fn update_handoffs_keep_the_launch_and_acknowledge_the_new_player() {
        let at = Instant::now();
        let mut games = launch(at);
        games.track_launch(at + Duration::from_secs(1), true, false);
        assert!(!games.track_launch(at + Duration::from_secs(2), false, false));
        assert!(games.track_launch(at + Duration::from_secs(3), false, true));
        assert!(games.launch_pending());
        assert!(games.launch_gone_since.is_none());
        assert!(!games.track_launch(at + Duration::from_secs(90), false, true));
        assert!(games.launch_started.is_some());
        assert!(games.track_launch(at + Duration::from_secs(91), true, false));
        assert_eq!(games.status.as_deref(), Some("Roblox is open."));
        assert!(!games.launch_pending());
        assert!(games.warning.is_none());
    }

    #[test]
    fn a_player_that_never_opened_still_times_out() {
        let at = Instant::now();
        let mut games = launch(at);
        assert!(!games.track_launch(at + Duration::from_secs(30), false, false));
        assert!(games.track_launch(at + Duration::from_secs(61), false, false));
        assert!(!games.launch_pending());
        assert_eq!(
            games.warning.as_deref(),
            Some("Roblox did not open within a minute. Try Play again.")
        );
    }
}
