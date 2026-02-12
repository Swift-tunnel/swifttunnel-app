use serde::Serialize;
use tauri::{AppHandle, Emitter, State};

use crate::events::{AUTH_STATE_CHANGED, AuthStateEvent};
use crate::state::AppState;

#[derive(Serialize)]
pub struct AuthStateResponse {
    pub state: String,
    pub email: Option<String>,
    pub user_id: Option<String>,
    pub is_tester: bool,
}

fn map_auth_state(auth_state: swifttunnel_core::auth::types::AuthState) -> AuthStateResponse {
    match auth_state {
        swifttunnel_core::auth::types::AuthState::LoggedIn(session) => AuthStateResponse {
            state: "logged_in".to_string(),
            email: Some(session.user.email),
            user_id: Some(session.user.id),
            is_tester: session.user.is_tester,
        },
        swifttunnel_core::auth::types::AuthState::LoggedOut => AuthStateResponse {
            state: "logged_out".to_string(),
            email: None,
            user_id: None,
            is_tester: false,
        },
        swifttunnel_core::auth::types::AuthState::LoggingIn => AuthStateResponse {
            state: "logging_in".to_string(),
            email: None,
            user_id: None,
            is_tester: false,
        },
        swifttunnel_core::auth::types::AuthState::AwaitingOAuthCallback(_) => AuthStateResponse {
            state: "awaiting_oauth".to_string(),
            email: None,
            user_id: None,
            is_tester: false,
        },
        swifttunnel_core::auth::types::AuthState::Error(msg) => AuthStateResponse {
            state: format!("error:{}", msg),
            email: None,
            user_id: None,
            is_tester: false,
        },
    }
}

async fn emit_auth_state(app: &AppHandle, state: &AppState) {
    let auth = state.auth_manager.lock().await;
    let auth_state = auth.get_state();
    let response = map_auth_state(auth_state);
    drop(auth);

    let payload = AuthStateEvent {
        state: response.state,
        email: response.email,
        user_id: response.user_id,
    };
    let _ = app.emit(AUTH_STATE_CHANGED, payload);
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
    let result = auth
        .complete_oauth_callback(&token, &callback_state)
        .await
        .map_err(|e| e.to_string());
    drop(auth);
    emit_auth_state(&app, &state).await;
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
    let result = auth.refresh_profile().await.map_err(|e| e.to_string());
    drop(auth);
    emit_auth_state(&app, &state).await;
    result
}
