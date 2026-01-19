//! Authentication manager - handles login/logout and token management

use super::http_client::AuthClient;
use super::storage::SecureStorage;
use super::types::{AuthError, AuthSession, AuthState, OAuthPendingState, UserInfo};
use chrono::{Duration, Utc};
use log::{debug, error, info};
use rand::Rng;
use std::sync::{Arc, Mutex};

const OAUTH_LOGIN_URL: &str = "https://swifttunnel.net/login";

/// Authentication manager
pub struct AuthManager {
    state: Arc<Mutex<AuthState>>,
    storage: SecureStorage,
    client: AuthClient,
}

impl AuthManager {
    /// Create a new AuthManager
    pub fn new() -> Result<Self, AuthError> {
        info!("========================================");
        info!("Initializing AuthManager...");
        let storage = SecureStorage::new()?;
        let client = AuthClient::new();

        // Try to load existing session (don't fail on session load errors)
        info!("Checking for stored session in Windows Credential Manager...");
        let initial_state = match storage.load_session() {
            Ok(Some(session)) => {
                info!("========================================");
                info!("FOUND STORED SESSION!");
                info!("  User email: {}", session.user.email);
                info!("  User ID: {}", session.user.id);
                info!("  Token length: {} chars", session.access_token.len());
                info!("  Refresh token length: {} chars", session.refresh_token.len());
                info!("  Expires at: {}", session.expires_at);
                info!("  Is expired: {}", session.is_expired());
                info!("  Expires soon: {}", session.expires_soon());
                if session.is_expired() {
                    info!("Session is expired but will be refreshed on first API call.");
                }
                info!("========================================");
                AuthState::LoggedIn(session)
            }
            Ok(None) => {
                info!("No stored session found in Windows Credential Manager.");
                info!("User needs to log in.");
                AuthState::LoggedOut
            }
            Err(e) => {
                // Log error but don't fail - just start logged out
                error!("Failed to load stored session: {}. Starting fresh.", e);
                AuthState::LoggedOut
            }
        };

        info!("AuthManager initialized with state: {:?}", match &initial_state {
            AuthState::LoggedIn(_) => "LoggedIn",
            AuthState::LoggedOut => "LoggedOut",
            AuthState::LoggingIn => "LoggingIn",
            AuthState::AwaitingOAuthCallback(_) => "AwaitingOAuthCallback",
            AuthState::Error(_) => "Error",
        });

        Ok(Self {
            state: Arc::new(Mutex::new(initial_state)),
            storage,
            client,
        })
    }

    /// Get the current auth state
    pub fn get_state(&self) -> AuthState {
        self.state.lock().unwrap().clone()
    }

    /// Check if user is logged in
    pub fn is_logged_in(&self) -> bool {
        matches!(self.get_state(), AuthState::LoggedIn(_))
    }

    /// Get the current user info if logged in
    pub fn get_user(&self) -> Option<UserInfo> {
        match self.get_state() {
            AuthState::LoggedIn(session) => Some(session.user),
            _ => None,
        }
    }

    /// Sign in with email and password
    pub async fn sign_in(&self, email: &str, password: &str) -> Result<(), AuthError> {
        info!("Signing in user: {}", email);

        // Set state to logging in
        {
            let mut state = self.state.lock().unwrap();
            *state = AuthState::LoggingIn;
        }

        // Call Supabase auth
        match self.client.sign_in_with_password(email, password).await {
            Ok(response) => {
                let session = AuthSession {
                    access_token: response.access_token,
                    refresh_token: response.refresh_token,
                    expires_at: Utc::now() + Duration::seconds(response.expires_in),
                    user: UserInfo {
                        id: response.user.id,
                        email: response.user.email.unwrap_or_else(|| email.to_string()),
                    },
                };

                // Store session
                self.storage.store_session(&session)?;

                // Update state
                {
                    let mut state = self.state.lock().unwrap();
                    *state = AuthState::LoggedIn(session);
                }

                info!("Sign in successful!");
                Ok(())
            }
            Err(e) => {
                error!("Sign in failed: {}", e);
                // Reset state to logged out with error
                {
                    let mut state = self.state.lock().unwrap();
                    *state = AuthState::Error(e.to_string());
                }
                Err(e)
            }
        }
    }

    /// Refresh the access token if needed
    pub async fn refresh_if_needed(&self) -> Result<(), AuthError> {
        let session = match self.get_state() {
            AuthState::LoggedIn(session) => session,
            _ => return Err(AuthError::NotAuthenticated),
        };

        if !session.expires_soon() {
            debug!("Token still valid, no refresh needed");
            return Ok(());
        }

        info!("Token expiring soon, refreshing...");

        let refresh_response = self.client.refresh_token(&session.refresh_token).await?;

        let new_session = AuthSession {
            access_token: refresh_response.access_token,
            refresh_token: refresh_response.refresh_token,
            expires_at: Utc::now() + Duration::seconds(refresh_response.expires_in),
            user: UserInfo {
                id: refresh_response.user.id,
                email: refresh_response.user.email.unwrap_or(session.user.email),
            },
        };

        // Store and update state
        self.storage.store_session(&new_session)?;

        {
            let mut state = self.state.lock().unwrap();
            *state = AuthState::LoggedIn(new_session);
        }

        info!("Token refreshed successfully");
        Ok(())
    }

    /// Get a valid access token, refreshing if needed
    pub async fn get_access_token(&self) -> Result<String, AuthError> {
        self.refresh_if_needed().await?;

        match self.get_state() {
            AuthState::LoggedIn(session) => Ok(session.access_token),
            _ => Err(AuthError::NotAuthenticated),
        }
    }

    /// Log out and clear stored credentials
    pub fn logout(&self) -> Result<(), AuthError> {
        info!("Logging out");

        self.storage.clear_session()?;

        {
            let mut state = self.state.lock().unwrap();
            *state = AuthState::LoggedOut;
        }

        info!("Logged out successfully");
        Ok(())
    }

    /// Cancel login attempt
    pub fn cancel_login(&self) {
        info!("Cancelling login");
        let mut state = self.state.lock().unwrap();
        *state = AuthState::LoggedOut;
    }

    /// Clear error state
    pub fn clear_error(&self) {
        let mut state = self.state.lock().unwrap();
        if matches!(*state, AuthState::Error(_)) {
            *state = AuthState::LoggedOut;
        }
    }

    /// Start Google OAuth sign-in flow
    /// Opens the browser to the login page and sets state to AwaitingOAuthCallback
    pub fn start_google_sign_in(&self) -> Result<String, AuthError> {
        info!("Starting Google OAuth sign-in flow");

        // Generate a random state parameter for CSRF protection
        let state: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        // Build the OAuth URL
        let oauth_url = format!(
            "{}?desktop=true&state={}&provider=google",
            OAUTH_LOGIN_URL,
            urlencoding::encode(&state)
        );

        info!("Opening browser to: {}", oauth_url);

        // Open the browser
        if let Err(e) = open::that(&oauth_url) {
            error!("Failed to open browser: {}", e);
            return Err(AuthError::ApiError(format!("Failed to open browser: {}", e)));
        }

        // Create the pending state
        let pending = OAuthPendingState {
            state: state.clone(),
            started_at: Utc::now(),
        };

        // Save OAuth state to disk for deep link callback after potential app restart
        if let Err(e) = self.storage.save_oauth_state(&pending) {
            error!("Failed to save OAuth state to disk: {}", e);
            // Continue anyway - this just means restart won't work
        }

        // Set state to awaiting OAuth callback
        {
            let mut auth_state = self.state.lock().unwrap();
            *auth_state = AuthState::AwaitingOAuthCallback(pending);
        }

        info!("OAuth flow started, waiting for callback with state: {}...", &state[..8]);
        Ok(state)
    }

    /// Complete OAuth callback - exchange token and verify
    /// Can work with state in memory (same instance) or loaded from disk (app restart via deep link)
    pub async fn complete_oauth_callback(
        &self,
        exchange_token: &str,
        callback_state: &str,
    ) -> Result<(), AuthError> {
        info!("Completing OAuth callback (exchange_token: {}..., state: {}...)",
            &exchange_token[..exchange_token.len().min(8)],
            &callback_state[..callback_state.len().min(8)]);

        // Try to get expected state from memory first, then from disk
        let expected_state = {
            let state = self.state.lock().unwrap();
            match &*state {
                AuthState::AwaitingOAuthCallback(pending) => {
                    // Check if the OAuth flow has expired (10 minutes)
                    if Utc::now() - pending.started_at > Duration::minutes(10) {
                        return Err(AuthError::ApiError("OAuth flow expired. Please try again.".to_string()));
                    }
                    Some(pending.state.clone())
                }
                _ => None,
            }
        };

        // If not in memory, try loading from disk (app was restarted via deep link)
        let expected_state = match expected_state {
            Some(s) => s,
            None => {
                info!("OAuth state not in memory, checking disk...");
                match self.storage.load_oauth_state() {
                    Ok(Some(pending)) => {
                        // Check if expired
                        if Utc::now() - pending.started_at > Duration::minutes(10) {
                            let _ = self.storage.clear_oauth_state();
                            return Err(AuthError::ApiError("OAuth flow expired. Please try again.".to_string()));
                        }
                        info!("Loaded OAuth state from disk");
                        pending.state
                    }
                    Ok(None) => {
                        return Err(AuthError::ApiError("Not waiting for OAuth callback. Please start sign-in again.".to_string()));
                    }
                    Err(e) => {
                        error!("Failed to load OAuth state from disk: {}", e);
                        return Err(AuthError::ApiError("Could not verify OAuth callback. Please try again.".to_string()));
                    }
                }
            }
        };

        if callback_state != expected_state {
            error!("State mismatch: expected {}, got {}", &expected_state[..8], &callback_state[..8.min(callback_state.len())]);
            // Reset state and clear disk
            {
                let mut state = self.state.lock().unwrap();
                *state = AuthState::Error("Security error: state mismatch. Please try again.".to_string());
            }
            let _ = self.storage.clear_oauth_state();
            return Err(AuthError::ApiError("Security error: state mismatch".to_string()));
        }

        // Clear OAuth state from disk now that we've validated it
        let _ = self.storage.clear_oauth_state();

        // Set state to logging in
        {
            let mut state = self.state.lock().unwrap();
            *state = AuthState::LoggingIn;
        }

        // Exchange the token for a magic link
        let exchange_response = match self.client.exchange_oauth_token(exchange_token, callback_state).await {
            Ok(response) => response,
            Err(e) => {
                error!("Failed to exchange OAuth token: {}", e);
                {
                    let mut state = self.state.lock().unwrap();
                    *state = AuthState::Error(e.to_string());
                }
                return Err(e);
            }
        };

        info!("Got magic link token for user: {} (token: {}...)",
            exchange_response.email,
            &exchange_response.token[..exchange_response.token.len().min(8)]);

        // Verify the magic link token to get access/refresh tokens
        let auth_response = match self
            .client
            .verify_magic_link(&exchange_response.email, &exchange_response.token)
            .await
        {
            Ok(response) => response,
            Err(e) => {
                error!("Failed to verify magic link: {}", e);
                {
                    let mut state = self.state.lock().unwrap();
                    *state = AuthState::Error(e.to_string());
                }
                return Err(e);
            }
        };

        // Create session
        let session = AuthSession {
            access_token: auth_response.access_token,
            refresh_token: auth_response.refresh_token,
            expires_at: Utc::now() + Duration::seconds(auth_response.expires_in),
            user: UserInfo {
                id: auth_response.user.id,
                email: auth_response.user.email.unwrap_or(exchange_response.email),
            },
        };

        // Store session
        self.storage.store_session(&session)?;

        // Update state
        {
            let mut state = self.state.lock().unwrap();
            *state = AuthState::LoggedIn(session);
        }

        info!("Google OAuth sign-in successful!");
        Ok(())
    }

    /// Cancel OAuth flow and return to logged out state
    pub fn cancel_oauth(&self) {
        info!("Cancelling OAuth flow");
        // Clear OAuth state from disk
        let _ = self.storage.clear_oauth_state();
        // Clear state in memory
        let mut state = self.state.lock().unwrap();
        if matches!(*state, AuthState::AwaitingOAuthCallback(_)) {
            *state = AuthState::LoggedOut;
        }
    }

    /// Check if currently awaiting OAuth callback
    pub fn is_awaiting_oauth(&self) -> bool {
        matches!(self.get_state(), AuthState::AwaitingOAuthCallback(_))
    }

    /// Get the pending OAuth state if awaiting callback
    pub fn get_pending_oauth_state(&self) -> Option<String> {
        match self.get_state() {
            AuthState::AwaitingOAuthCallback(pending) => Some(pending.state),
            _ => None,
        }
    }
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new().expect("Failed to create AuthManager")
    }
}
