use crate::state::AppState;
use serde::Serialize;
use swifttunnel_core::roblox_library::{
    GameEntry, GameLibrary, RobloxClient, join_url, library_path,
};
use tauri::State;

pub const LIBRARY_CHANGED: &str = "roblox-library-changed";

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
}

#[derive(Default)]
pub struct GamesState {
    pub library: Option<GameLibrary>,
    pub current: Option<CurrentGame>,
    pub warning: Option<String>,
}

#[derive(Serialize)]
pub struct LibrarySnapshot {
    pub entries: Vec<GameEntry>,
    pub current: Option<CurrentGame>,
    pub warning: Option<String>,
    pub notify_joins: bool,
}

impl GamesState {
    fn library(&mut self) -> Result<&GameLibrary, String> {
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
    })
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
    place_id: String,
    client: RobloxClient,
    favourite: bool,
) -> Result<(), String> {
    state
        .games
        .lock()
        .mutate(|lib| lib.set_favourite(&place_id, client, favourite))
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
fn launch_url(url: &str) -> Result<(), String> {
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
fn launch_url(_: &str) -> Result<(), String> {
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
        e.place_id == place_id && e.client == client && e.name == format!("Place {place_id}")
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
    state.games.lock().mutate(|lib| {
        lib.set_name(place_id, client, name);
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
