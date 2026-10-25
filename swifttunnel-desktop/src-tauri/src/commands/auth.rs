use serde::Serialize;
use tauri::{AppHandle, Emitter, State};

use crate::events::{AUTH_STATE_CHANGED, AuthStateEvent};
use crate::state::AppState;
use swifttunnel_core::auth::types::{AuthError, AuthState};
use swifttunnel_core::settings::AppSettings;
use swifttunnel_core::structs::PowerPlan;

#[derive(Serialize)]
pub struct AuthStateResponse {
    pub state: String,
    pub email: Option<String>,
    pub user_id: Option<String>,
    pub is_tester: bool,
    pub is_banned: bool,
    pub banned_reason: Option<String>,
    pub banned_at: Option<String>,
}

fn map_auth_state(auth_state: AuthState) -> AuthStateResponse {
    match auth_state {
        AuthState::LoggedIn(session) => AuthStateResponse {
            state: "logged_in".to_string(),
            email: Some(session.user.email),
            user_id: Some(session.user.id),
            is_tester: session.user.is_tester,
            is_banned: false,
            banned_reason: None,
            banned_at: None,
        },
        AuthState::Banned(session) => AuthStateResponse {
            state: "banned".to_string(),
            email: Some(session.user.email),
            user_id: Some(session.user.id),
            is_tester: false,
            is_banned: true,
            banned_reason: session.user.banned_reason,
            banned_at: session.user.banned_at,
        },
        AuthState::LoggedOut => AuthStateResponse {
            state: "logged_out".to_string(),
            email: None,
            user_id: None,
            is_tester: false,
            is_banned: false,
            banned_reason: None,
            banned_at: None,
        },
        AuthState::LoggingIn => AuthStateResponse {
            state: "logging_in".to_string(),
            email: None,
            user_id: None,
            is_tester: false,
            is_banned: false,
            banned_reason: None,
            banned_at: None,
        },
        AuthState::AwaitingOAuthCallback(_) => AuthStateResponse {
            state: "awaiting_oauth".to_string(),
            email: None,
            user_id: None,
            is_tester: false,
            is_banned: false,
            banned_reason: None,
            banned_at: None,
        },
        AuthState::Error(msg) => AuthStateResponse {
            state: format!("error:{}", msg),
            email: None,
            user_id: None,
            is_tester: false,
            is_banned: false,
            banned_reason: None,
            banned_at: None,
        },
    }
}

fn is_auth_banned(auth_state: &AuthState) -> bool {
    matches!(auth_state, AuthState::Banned(_))
}

fn apply_banned_session_cleanup_settings(settings: &mut AppSettings) {
    settings.resume_vpn_on_startup = false;
    settings.config.system_optimization.power_plan = PowerPlan::Balanced;
    settings.config.system_optimization.previous_power_plan = None;
}

fn persist_signed_out_settings(
    settings: &parking_lot::Mutex<AppSettings>,
    persist: impl FnOnce(&AppSettings) -> Result<(), String>,
) -> Result<(), String> {
    // Keep the reconnect restriction in memory even if storage fails. The
    // credentials have already been removed, so rolling it back is unsafe.
    let mut current = settings.lock();
    current.resume_vpn_on_startup = false;
    persist(&current)
}

fn restore_global_after_temporary_settings(
    pending: bool,
    restore: impl FnOnce() -> Result<(), String>,
) -> Result<bool, String> {
    if pending {
        return Ok(false);
    }
    restore().map(|()| true)
}

pub(crate) async fn emit_auth_state(app: &AppHandle, state: &AppState) {
    let response = map_auth_state(state.auth_state.get_state());

    let payload = AuthStateEvent {
        state: response.state,
        email: response.email,
        user_id: response.user_id,
        is_tester: response.is_tester,
        is_banned: response.is_banned,
        banned_reason: response.banned_reason,
        banned_at: response.banned_at,
    };
    let _ = app.emit(AUTH_STATE_CHANGED, payload);
}

pub(crate) async fn cleanup_banned_session(state: &AppState) -> bool {
    let auth_state = {
        let auth = state.auth_manager.lock().await;
        auth.get_state()
    };

    if !is_auth_banned(&auth_state) {
        return false;
    }

    log::warn!("Account is banned; disconnecting VPN and restoring saved boosts");

    if let Err(e) = crate::commands::vpn::disconnect_and_persist(state).await {
        log::warn!("Failed to disconnect VPN after ban detection: {}", e);
    }

    // Disconnect uses the auth manager to settle usage, so never retain its
    // lock across the await above. Restore work itself is synchronous and can
    // wait on Windows commands or slow storage.
    let operation = match super::optimizer::wait_for_config_change().await {
        Ok(operation) => operation,
        Err(error) => {
            log::warn!("Ban cleanup: {error}");
            return true;
        }
    };
    let auth = state.auth_manager.clone();
    let performance = state.performance_monitor.clone();
    let system = state.system_optimizer.clone();
    let network = state.network_booster.clone();
    let roblox = state.roblox_optimizer.clone();
    let settings = state.settings.clone();
    match tauri::async_runtime::spawn_blocking(move || {
        let _operation = operation;
        // Waiting behind another apply must not restore settings for an
        // account that has since signed out or signed in successfully.
        if !is_auth_banned(&auth.blocking_lock().get_state()) {
            return false;
        }
        let roblox_pid = performance.lock().get_roblox_pid().unwrap_or(0);
        {
            let mut optimizer = system.lock();
            if let Err(error) = optimizer.restore(roblox_pid) {
                log::warn!("Failed to restore system boosts after ban detection: {error}");
            }
            if let Err(error) = optimizer.cleanup_swifttunnel_power_plan_after_ban() {
                log::warn!(
                    "Failed to clean up SwiftTunnel power plan after ban detection: {error}"
                );
            }
        }
        if let Err(error) = network.lock().restore() {
            log::warn!("Failed to restore network boosts after ban detection: {error}");
        }
        {
            let optimizer = roblox.lock();
            match restore_global_after_temporary_settings(
                swifttunnel_core::roblox_game_profile::pending()
                    || swifttunnel_core::roblox_launch_flags::pending(),
                || {
                    optimizer
                        .restore_settings()
                        .map_err(|error| error.to_string())
                },
            ) {
                Ok(false) => {
                    log::info!("Global Roblox restore deferred until per-game recovery finishes")
                }
                Err(error) => {
                    log::warn!("Failed to restore Roblox boosts after ban detection: {error}")
                }
                Ok(true) => {}
            }
        }
        // Protect only this short account/settings commit. A new login may
        // occur during Windows restoration, but cannot inherit this late write.
        let current_auth = auth.blocking_lock();
        if !is_auth_banned(&current_auth.get_state()) {
            return false;
        }
        let mut current = settings.lock();
        apply_banned_session_cleanup_settings(&mut current);
        if let Err(error) = swifttunnel_core::settings::save_settings(&current) {
            log::warn!("Failed to persist boost cleanup after ban detection: {error}");
        }
        true
    })
    .await
    {
        Ok(banned) => banned,
        Err(error) => {
            log::warn!("Ban cleanup worker could not finish: {error}");
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banned_cleanup_settings_disable_power_plan_resume() {
        let mut settings = AppSettings {
            resume_vpn_on_startup: true,
            ..Default::default()
        };
        settings.config.system_optimization.power_plan = PowerPlan::SwiftTunnel;
        settings.config.system_optimization.previous_power_plan = Some(PowerPlan::Balanced);

        apply_banned_session_cleanup_settings(&mut settings);

        assert!(!settings.resume_vpn_on_startup);
        assert_eq!(
            settings.config.system_optimization.power_plan,
            PowerPlan::Balanced
        );
        assert!(
            settings
                .config
                .system_optimization
                .previous_power_plan
                .is_none()
        );
    }

    #[test]
    fn sign_out_persistence_cannot_overwrite_a_competing_preference_write() {
        let settings = parking_lot::Mutex::new(AppSettings {
            resume_vpn_on_startup: true,
            idle_when_unfocused: true,
            ..Default::default()
        });
        let mut disk = settings.lock().clone();
        persist_signed_out_settings(&settings, |snapshot| {
            // Model another settings writer arriving during the save. If it
            // can enter, the logout snapshot would overwrite its disk commit.
            if let Some(mut competing) = settings.try_lock() {
                competing.idle_when_unfocused = false;
            }
            disk = snapshot.clone();
            Ok(())
        })
        .unwrap();
        assert_eq!(
            disk.idle_when_unfocused,
            settings.lock().idle_when_unfocused
        );
        assert!(!disk.resume_vpn_on_startup);
    }

    #[test]
    fn failed_sign_out_save_retains_the_reconnect_restriction_and_other_preferences() {
        let settings = parking_lot::Mutex::new(AppSettings {
            resume_vpn_on_startup: true,
            idle_when_unfocused: false,
            ..Default::default()
        });
        assert!(persist_signed_out_settings(&settings, |_| Err("locked file".into())).is_err());
        assert!(!settings.lock().resume_vpn_on_startup);
        assert!(!settings.lock().idle_when_unfocused);
    }

    #[test]
    fn global_restore_waits_for_per_game_recovery_and_does_not_hide_restore_errors() {
        assert_eq!(
            restore_global_after_temporary_settings(true, || panic!(
                "temporary settings are still owned by recovery"
            )),
            Ok(false)
        );
        let restored = std::cell::Cell::new(false);
        assert_eq!(
            restore_global_after_temporary_settings(false, || {
                restored.set(true);
                Ok(())
            }),
            Ok(true)
        );
        assert!(restored.get());
        assert_eq!(
            restore_global_after_temporary_settings(false, || Err("locked backup".into())),
            Err("locked backup".into())
        );
    }
}

pub(crate) async fn apply_ban_cleanup(app: &AppHandle, state: &AppState) -> bool {
    if cleanup_banned_session(state).await {
        emit_auth_state(app, state).await;
        return true;
    }
    false
}

#[tauri::command]
pub async fn auth_get_state(state: State<'_, AppState>) -> Result<AuthStateResponse, String> {
    Ok(map_auth_state(state.auth_state.get_state()))
}

/// The forced-update ("please update") message if the server has locked this
/// build out (old-build lockout), else null. The UI polls this to show the
/// blocking update gate. Sync + lock-free: it just reads a latched flag.
#[tauri::command]
pub fn auth_update_required() -> Option<String> {
    swifttunnel_core::auth::update_required_message()
}

#[tauri::command]
pub async fn auth_start_oauth(
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<String, String> {
    let auth_manager = state.auth_manager.clone();
    // Listener startup and Windows shell launch are blocking operations.
    let result = tauri::async_runtime::spawn_blocking(move || {
        auth_manager
            .blocking_lock()
            .start_google_sign_in()
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("Browser sign-in task failed: {error}"))?;
    emit_auth_state(&app, &state).await;
    result
}

#[tauri::command]
pub async fn auth_login(
    state: State<'_, AppState>,
    app: AppHandle,
    email: String,
    password: String,
) -> Result<(), String> {
    let auth = state.auth_manager.lock().await;
    let login_result = auth.sign_in(email.trim(), &password).await;
    let should_run_ban_cleanup = matches!(login_result, Ok(()) | Err(AuthError::UserBanned(_)));
    let result = login_result.map_err(|e| e.to_string());
    drop(auth);

    let emitted = should_run_ban_cleanup && apply_ban_cleanup(&app, &state).await;
    if !emitted {
        emit_auth_state(&app, &state).await;
    }

    result
}

#[derive(Serialize)]
pub struct OAuthPollResult {
    pub completed: bool,
    pub token: Option<String>,
    pub state: Option<String>,
}

#[tauri::command]
pub async fn auth_poll_oauth(state: State<'_, AppState>) -> Result<OAuthPollResult, String> {
    let auth = state.auth_manager.lock().await;
    Ok(match auth.poll_oauth_callback() {
        Some(callback) => OAuthPollResult {
            completed: true,
            token: Some(callback.token),
            state: Some(callback.state),
        },
        None => OAuthPollResult {
            completed: false,
            token: None,
            state: None,
        },
    })
}

#[tauri::command]
pub async fn auth_cancel_oauth(state: State<'_, AppState>, app: AppHandle) -> Result<(), String> {
    let auth_manager = state.auth_manager.clone();
    tauri::async_runtime::spawn_blocking(move || auth_manager.blocking_lock().cancel_oauth())
        .await
        .map_err(|error| format!("Browser sign-in cancellation failed: {error}"))?;
    emit_auth_state(&app, &state).await;
    Ok(())
}

#[tauri::command]
pub async fn auth_complete_oauth(
    state: State<'_, AppState>,
    app: AppHandle,
    token: String,
    callback_state: String,
) -> Result<(), String> {
    let auth = state.auth_manager.lock().await;
    let complete_result = auth.complete_oauth_callback(&token, &callback_state).await;
    let should_run_ban_cleanup = matches!(complete_result, Ok(()) | Err(AuthError::UserBanned(_)));
    let result = complete_result.map_err(|e| e.to_string());
    drop(auth);
    let emitted = should_run_ban_cleanup && apply_ban_cleanup(&app, &state).await;
    if !emitted {
        emit_auth_state(&app, &state).await;
    }
    result
}

#[tauri::command]
pub async fn auth_logout(state: State<'_, AppState>, app: AppHandle) -> Result<(), String> {
    let auth_manager = state.auth_manager.clone();
    let discord_manager = state.discord_manager.clone();
    let settings = state.settings.clone();
    // Vault/file access can wait on Windows or storage. Keep it off the async
    // executor, and retain account-action ordering through the final save.
    let result = tauri::async_runtime::spawn_blocking(move || {
        let auth = auth_manager.blocking_lock();
        auth.logout().map_err(|e| e.to_string())?;
        discord_manager.lock().clear();
        persist_signed_out_settings(&settings, swifttunnel_core::settings::save_settings)
            .map_err(|error| {
                log::warn!("Failed to persist logout reconnect settings: {error}");
                "Signed out, but automatic connection settings could not be saved. Close SwiftTunnel and try again.".to_string()
            })
    })
    .await
    .map_err(|error| {
        log::warn!("Sign-out worker could not finish: {error}");
        "Could not finish signing out. Close SwiftTunnel and try again.".to_string()
    })
    .and_then(|result| result);

    emit_auth_state(&app, &state).await;
    result
}

#[tauri::command]
pub async fn auth_refresh_profile(
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    let auth = state.auth_manager.lock().await;
    let refresh_result = auth.refresh_profile().await;
    let should_run_ban_cleanup = matches!(refresh_result, Ok(()) | Err(AuthError::UserBanned(_)));
    let result = refresh_result.map_err(|e| e.to_string());
    drop(auth);
    let emitted = should_run_ban_cleanup && apply_ban_cleanup(&app, &state).await;
    if !emitted {
        emit_auth_state(&app, &state).await;
    }
    result
}
