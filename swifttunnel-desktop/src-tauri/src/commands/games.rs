use crate::state::AppState;
use serde::Serialize;
use swifttunnel_core::roblox_library::{GameEntry, GameLibrary, RobloxClient, library_path};
use tauri::{Emitter, State};

pub const LIBRARY_CHANGED: &str = "roblox-library-changed";

/// Library writes hold the state lock through the atomic save. Both acquiring
/// that lock and file I/O belong off the UI and async executor threads.
pub(crate) async fn library_task<T: Send + 'static>(
    games: std::sync::Arc<parking_lot::Mutex<GamesState>>,
    work: impl FnOnce(&mut GamesState) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(move || work(&mut games.lock()))
        .await
        .map_err(|e| e.to_string())?
}

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
    static BATCH_SLOT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    let Ok(_batch) = BATCH_SLOT.try_acquire() else {
        return Ok(());
    };
    let targets: Vec<_> = state
        .games
        .lock()
        .library()?
        .entries
        .iter()
        .filter(|e| e.icon_url.is_none() || e.universe_id.is_none())
        .map(|e| (e.place_id.clone(), e.client))
        .collect();
    for (place, client) in targets {
        if refresh_name(&state, &place, client).await == Ok(true) {
            let _ = app.emit(LIBRARY_CHANGED, ());
        }
    }
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

    pub(crate) fn library(&mut self) -> Result<&GameLibrary, String> {
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
pub async fn games_get_library(state: State<'_, AppState>) -> Result<LibrarySnapshot, String> {
    library_task(state.games.clone(), |games| {
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
    })
    .await
}
#[tauri::command]
pub async fn games_dismiss_recovery(state: State<'_, AppState>) -> Result<(), String> {
    library_task(state.games.clone(), |games| {
        games.recovery = None;
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn games_set_notifications(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<(), String> {
    library_task(state.games.clone(), move |games| {
        games.mutate(|lib| {
            lib.notify_joins = enabled;
            Ok(())
        })
    })
    .await
}

#[tauri::command]
pub async fn games_set_favourite(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    place_id: String,
    client: RobloxClient,
    favourite: bool,
) -> Result<(), String> {
    library_task(state.games.clone(), move |games| {
        let warning = games.warning.clone();
        games.mutate(|lib| lib.set_favourite(&place_id, client, favourite))?;
        games.warning = warning;
        Ok(())
    })
    .await?;
    let _ = app.emit(LIBRARY_CHANGED, ());
    Ok(())
}

#[tauri::command]
pub async fn games_forget(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    place_id: String,
    client: RobloxClient,
) -> Result<(), String> {
    library_task(state.games.clone(), move |games| {
        games.mutate(|lib| {
            lib.forget(&place_id, client);
            Ok(())
        })
    })
    .await?;
    let _ = app.emit(LIBRARY_CHANGED, ());
    Ok(())
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
            && (e.name == format!("Place {place_id}")
                || e.icon_url.is_none()
                || e.universe_id.is_none())
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
    let place_id = place_id.to_owned();
    let name = name.to_owned();
    library_task(state.games.clone(), move |games| {
        games.mutate(|lib| {
            lib.set_universe(&place_id, client, &universe.to_string());
            lib.set_name(&place_id, client, &name);
            if let Some(icon) = icon {
                lib.set_icon(&place_id, client, &icon);
            }
            Ok(())
        })
    })
    .await?;
    Ok(true)
}

#[tauri::command]
pub async fn games_add_favourite(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    place_id: String,
    client: Option<RobloxClient>,
) -> Result<(), String> {
    let client = client.unwrap_or_default();
    let saved_place = place_id.clone();
    library_task(state.games.clone(), move |games| {
        games.mutate(|lib| lib.set_favourite(&saved_place, client, true))
    })
    .await?;
    let _ = app.emit(LIBRARY_CHANGED, ());
    // Saving a game must not wait for up to three metadata requests. Its
    // numeric label is usable immediately; name and icon arrive in background.
    state.runtime.spawn(async move {
        use tauri::Manager;
        let state = app.state::<AppState>();
        if refresh_name(&state, &place_id, client).await == Ok(true) {
            let _ = app.emit(LIBRARY_CHANGED, ());
        }
    });
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
