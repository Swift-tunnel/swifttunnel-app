//! Authentication manager - handles login/logout and token management

use super::http_client::AuthClient;
use super::oauth_server::{OAuthServer, OAuthServerResult, DEFAULT_OAUTH_PORT};
use super::storage::SecureStorage;
use super::types::{AuthError, AuthSession, AuthState, OAuthPendingState, UserInfo};
use chrono::{Duration, Utc};
use log::{debug, error, info, warn};
use rand::Rng;
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

const OAUTH_LOGIN_URL: &str = "https://swifttunnel.net/login";

/// Maximum number of token refresh retries
const MAX_REFRESH_RETRIES: u32 = 3;

/// Authentication manager
pub struct AuthManager {
    state: Arc<Mutex<AuthState>>,
    storage: SecureStorage,
    client: AuthClient,
    /// Active OAuth server (if awaiting callback)
    oauth_server: Arc<Mutex<Option<OAuthServer>>>,
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
            oauth_server: Arc::new(Mutex::new(None)),
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
    ///
    /// This method implements robust token refresh with:
    /// - Automatic refresh when token is expired OR expiring soon
    /// - Retry logic with exponential backoff
    /// - Silent failure handling (keeps user logged in with stale data)
    pub async fn refresh_if_needed(&self) -> Result<(), AuthError> {
        let session = match self.get_state() {
            AuthState::LoggedIn(session) => session,
            _ => return Err(AuthError::NotAuthenticated),
        };

        // Check if refresh is needed (expired OR expiring soon)
        let needs_refresh = session.is_expired() || session.expires_soon();
        if !needs_refresh {
            debug!("Token still valid, no refresh needed");
            return Ok(());
        }

        if session.is_expired() {
            info!("Token expired, attempting refresh...");
        } else {
            info!("Token expiring soon, refreshing proactively...");
        }

        // Try to refresh with retries
        let mut last_error = None;
        for attempt in 1..=MAX_REFRESH_RETRIES {
            match self.try_refresh_token(&session).await {
                Ok(new_session) => {
                    // Store and update state
                    if let Err(e) = self.storage.store_session(&new_session) {
                        warn!("Failed to store refreshed session: {}", e);
                        // Continue anyway - session is valid in memory
                    }

                    // Reset refresh failure count on success
                    self.storage.reset_refresh_failures();

                    {
                        let mut state = self.state.lock().unwrap();
                        *state = AuthState::LoggedIn(new_session);
                    }

                    info!("Token refreshed successfully on attempt {}", attempt);
                    return Ok(());
                }
                Err(e) => {
                    warn!("Token refresh attempt {} failed: {}", attempt, e);
                    last_error = Some(e);

                    // Wait before retry (exponential backoff: 1s, 2s, 4s)
                    if attempt < MAX_REFRESH_RETRIES {
                        let delay = StdDuration::from_secs(1 << (attempt - 1));
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        // All retries failed - track the failure
        let failure_count = self.storage.increment_refresh_failures();
        warn!("Token refresh failed after {} attempts (total failures: {})", MAX_REFRESH_RETRIES, failure_count);

        // If too many consecutive failures, the refresh token may be invalid
        // But we don't kick the user out - let them continue with stale data
        // They'll only be forced to re-login when they try an action that requires valid auth
        if failure_count >= 5 {
            warn!("Too many consecutive refresh failures - refresh token may be invalid");
            // Don't return error yet - let the user continue until an API call fails
        }

        // Return OK even though refresh failed - user stays logged in with stale data
        // This prevents "session expired" messages for temporary network issues
        if !session.is_expired() {
            // Token not yet expired, user can continue
            info!("Refresh failed but token not yet expired - continuing with existing session");
            Ok(())
        } else {
            // Token is expired - we couldn't refresh it
            // But we still don't kick the user out immediately
            // Let the API call that needs auth decide what to do
            warn!("Token expired and refresh failed - user may need to re-login soon");
            Err(last_error.unwrap_or(AuthError::ApiError("Token refresh failed".to_string())))
        }
    }

    /// Attempt a single token refresh
    async fn try_refresh_token(&self, session: &AuthSession) -> Result<AuthSession, AuthError> {
        let refresh_response = self.client.refresh_token(&session.refresh_token).await?;

        Ok(AuthSession {
            access_token: refresh_response.access_token,
            refresh_token: refresh_response.refresh_token,
            expires_at: Utc::now() + Duration::seconds(refresh_response.expires_in),
            user: UserInfo {
                id: refresh_response.user.id,
                email: refresh_response.user.email.unwrap_or_else(|| session.user.email.clone()),
            },
        })
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

    /// Start Google OAuth sign-in flow using localhost callback server
    ///
    /// This method:
    /// 1. Starts a localhost HTTP server to receive the OAuth callback
    /// 2. Opens the browser to the login page with the server port
    /// 3. Sets state to AwaitingOAuthCallback
    ///
    /// Returns the OAuth state string for verification.
    pub fn start_google_sign_in(&self) -> Result<String, AuthError> {
        info!("Starting Google OAuth sign-in flow with localhost server");

        // Stop any existing OAuth server
        {
            let mut server_guard = self.oauth_server.lock().unwrap();
            if let Some(mut server) = server_guard.take() {
                info!("Stopping previous OAuth server");
                server.stop();
            }
        }

        // Start the localhost OAuth server
        let oauth_server = match OAuthServer::start() {
            Ok(server) => server,
            Err(e) => {
                error!("Failed to start OAuth server: {}", e);
                return Err(AuthError::ApiError(format!("Failed to start OAuth server: {}", e)));
            }
        };

        let port = oauth_server.port();
        info!("OAuth server started on port {}", port);

        // Generate a random state parameter for CSRF protection
        let state: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        // Build the OAuth URL with the redirect port
        let oauth_url = format!(
            "{}?desktop=true&state={}&provider=google&redirect_port={}",
            OAUTH_LOGIN_URL,
            urlencoding::encode(&state),
            port
        );

        info!("Opening browser to: {}", oauth_url);

        // Open the browser
        if let Err(e) = open::that(&oauth_url) {
            error!("Failed to open browser: {}", e);
            // Clean up the server
            let mut server_guard = self.oauth_server.lock().unwrap();
            *server_guard = None;
            return Err(AuthError::ApiError(format!("Failed to open browser: {}", e)));
        }

        // Store the OAuth server
        {
            let mut server_guard = self.oauth_server.lock().unwrap();
            *server_guard = Some(oauth_server);
        }

        // Create the pending state
        let pending = OAuthPendingState {
            state: state.clone(),
            started_at: Utc::now(),
        };

        // Set state to awaiting OAuth callback
        {
            let mut auth_state = self.state.lock().unwrap();
            *auth_state = AuthState::AwaitingOAuthCallback(pending);
        }

        info!("OAuth flow started, waiting for localhost callback with state: {}...", &state[..8]);
        Ok(state)
    }

    /// Poll for OAuth callback (non-blocking)
    ///
    /// Call this periodically to check if the OAuth callback has been received.
    /// Returns Some(callback_data) if callback received, None otherwise.
    pub fn poll_oauth_callback(&self) -> Option<super::oauth_server::OAuthCallbackData> {
        let server_guard = self.oauth_server.lock().unwrap();
        if let Some(ref server) = *server_guard {
            server.try_recv_callback()
        } else {
            None
        }
    }

    /// Get the OAuth server port (if active)
    pub fn get_oauth_port(&self) -> Option<u16> {
        let server_guard = self.oauth_server.lock().unwrap();
        server_guard.as_ref().map(|s| s.port())
    }

    /// Complete OAuth callback - exchange token and verify
    ///
    /// This is called when the localhost server receives the callback.
    /// The state parameter is verified against the expected state in memory.
    pub async fn complete_oauth_callback(
        &self,
        exchange_token: &str,
        callback_state: &str,
    ) -> Result<(), AuthError> {
        info!("Completing OAuth callback (exchange_token: {}..., state: {}...)",
            &exchange_token[..exchange_token.len().min(8)],
            &callback_state[..callback_state.len().min(8)]);

        // Get expected state from memory
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

        let expected_state = match expected_state {
            Some(s) => s,
            None => {
                error!("OAuth state not found in memory");
                return Err(AuthError::ApiError("Not waiting for OAuth callback. Please start sign-in again.".to_string()));
            }
        };

        if callback_state != expected_state {
            error!("State mismatch: expected {}..., got {}...",
                &expected_state[..expected_state.len().min(8)],
                &callback_state[..callback_state.len().min(8)]);
            // Reset state
            {
                let mut state = self.state.lock().unwrap();
                *state = AuthState::Error("Security error: state mismatch. Please try again.".to_string());
            }
            // Stop OAuth server
            self.stop_oauth_server();
            return Err(AuthError::ApiError("Security error: state mismatch".to_string()));
        }

        // Stop the OAuth server now that we've received the callback
        self.stop_oauth_server();

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

        // Stop the OAuth server
        self.stop_oauth_server();

        // Clear state in memory
        let mut state = self.state.lock().unwrap();
        if matches!(*state, AuthState::AwaitingOAuthCallback(_)) {
            *state = AuthState::LoggedOut;
        }
    }

    /// Stop the OAuth server if it's running
    fn stop_oauth_server(&self) {
        let mut server_guard = self.oauth_server.lock().unwrap();
        if let Some(mut server) = server_guard.take() {
            info!("Stopping OAuth server");
            server.stop();
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
