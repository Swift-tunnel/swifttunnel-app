use std::sync::Arc;

use parking_lot::Mutex;
use swifttunnel_core::roblox_proxy::goodbyedpi::{
    CountryBanBypassController, CountryBanBypassSyncOutcome,
};
use tauri::{AppHandle, Emitter};

use crate::events::COUNTRY_BAN_BYPASS_UNAVAILABLE;
use crate::state::AppState;

pub(crate) fn sync_country_ban_bypass_controller(
    controller: &Arc<Mutex<CountryBanBypassController>>,
    enabled: bool,
) -> CountryBanBypassSyncOutcome {
    controller.lock().sync(enabled)
}

pub(crate) fn stop_country_ban_bypass_controller(state: &AppState) -> bool {
    state.country_ban_bypass.lock().stop()
}

pub(crate) fn log_and_emit_country_ban_bypass_outcome(
    app: &AppHandle,
    source: &str,
    outcome: &CountryBanBypassSyncOutcome,
) {
    match outcome {
        CountryBanBypassSyncOutcome::Started => {
            log::info!("Country ban bypass helper started from {source}");
        }
        CountryBanBypassSyncOutcome::AlreadyRunning => {
            log::debug!("Country ban bypass helper already running from {source}");
        }
        CountryBanBypassSyncOutcome::Stopped => {
            log::info!("Country ban bypass helper stopped from {source}");
        }
        CountryBanBypassSyncOutcome::AlreadyStopped => {
            log::debug!("Country ban bypass helper already stopped from {source}");
        }
        CountryBanBypassSyncOutcome::Unavailable(message)
        | CountryBanBypassSyncOutcome::Failed(message) => {
            log::warn!("Country ban bypass unavailable from {source}: {message}");
            let _ = app.emit(COUNTRY_BAN_BYPASS_UNAVAILABLE, ());
        }
    }
}

pub(crate) async fn sync_country_ban_bypass_from_state(
    app: &AppHandle,
    state: &AppState,
    source: &'static str,
) {
    let enabled = state.settings.lock().enable_country_ban;
    let controller = state.country_ban_bypass.clone();
    match tauri::async_runtime::spawn_blocking(move || {
        sync_country_ban_bypass_controller(&controller, enabled)
    })
    .await
    {
        Ok(outcome) => log_and_emit_country_ban_bypass_outcome(app, source, &outcome),
        Err(e) => {
            log::warn!("Country ban bypass sync task failed from {source}: {e}");
            let _ = app.emit(COUNTRY_BAN_BYPASS_UNAVAILABLE, ());
        }
    }
}
