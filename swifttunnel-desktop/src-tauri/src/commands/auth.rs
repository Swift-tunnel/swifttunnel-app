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

pub(crate) async fn emit_auth_state(app: &AppHandle, state: &AppState) {
    let auth = state.auth_manager.lock().await;
    let auth_state = auth.get_state();
    let response = map_auth_state(auth_state);
    drop(auth);

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

    let roblox_pid = {
        let mut monitor = state.performance_monitor.lock();
        monitor.get_roblox_pid().unwrap_or(0)
    };

    {
        let mut optimizer = state.system_optimizer.lock();
        if let Err(e) = optimizer.restore(roblox_pid) {
            log::warn!("Failed to restore system boosts after ban detection: {}", e);
        }
        if let Err(e) = optimizer.cleanup_swifttunnel_power_plan_after_ban() {
            log::warn!(
                "Failed to clean up SwiftTunnel power plan after ban detection: {}",
                e
            );
        }
    }
    if let Err(e) = state.network_booster.lock().restore() {
        log::warn!(
            "Failed to restore network boosts after ban detection: {}",
            e
        );
    }
    if let Err(e) = state.roblox_optimizer.lock().restore_settings() {
        log::warn!("Failed to restore Roblox boosts after ban detection: {}", e);
    }

    let snapshot = {
        let mut settings = state.settings.lock();
        apply_banned_session_cleanup_settings(&mut settings);
        settings.clone()
    };

    if let Err(e) = swifttunnel_core::settings::save_settings(&snapshot) {
        log::warn!("Failed to persist boost cleanup after ban detection: {}", e);
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banned_cleanup_settings_disable_power_plan_resume() {
        let mut settings = AppSettings::default();
        settings.resume_vpn_on_startup = true;
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
    let auth = state.auth_manager.lock().await;
    let auth_state = auth.get_state();
    Ok(map_auth_state(auth_state))
}

#[tauri::command]
pub async fn auth_start_oauth(
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<String, String> {
    let auth = state.auth_manager.lock().await;
    let result = auth.start_google_sign_in().map_err(|e| e.to_string());
    drop(auth);
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
    let auth = state.auth_manager.lock().await;
    auth.cancel_oauth();
    drop(auth);
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
    let auth = state.auth_manager.lock().await;
    let result = auth.logout().map_err(|e| e.to_string());
    drop(auth);

    if result.is_ok() {
        let mut discord = state.discord_manager.lock();
        discord.clear();

        let mut settings = state.settings.lock();
        settings.resume_vpn_on_startup = false;
        let snapshot = settings.clone();
        drop(settings);
        if let Err(e) = swifttunnel_core::settings::save_settings(&snapshot) {
            log::warn!("Failed to persist logout reconnect settings: {}", e);
        }
    }

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
