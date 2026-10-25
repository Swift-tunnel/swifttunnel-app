//! Authentication manager - handles login/logout and token management

use super::http_client::{AuthClient, UserProfileResponse};
use super::oauth_server::OAuthServer;
use super::storage::SecureStorage;
use super::types::{
    AuthError, AuthSession, AuthState, OAuthPendingState, SupabaseAuthResponse, SupabaseUser,
    UserInfo,
};
use chrono::{Duration, Utc};
use log::{debug, error, info, warn};
use parking_lot::Mutex;
use rand::Rng;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};
use url::form_urlencoded;

/// Path of the sign-in page opened in the user's browser.
///
/// The host comes from `current_api_base` rather than being fixed here. A
/// filter that kills TLS to our domain kills this page too, so somebody in that
/// position could not sign in at all: the browser would sit on a failed
/// handshake with no way to say why. Following whichever host the client found
/// working means the browser is sent somewhere it can actually reach.
const OAUTH_LOGIN_PATH: &str = "/login";

/// Maximum number of token refresh retries
const MAX_REFRESH_RETRIES: u32 = 3;
const TRANSIENT_REFRESH_BACKOFF: StdDuration = StdDuration::from_secs(30);

#[derive(Clone, Copy)]
enum RefreshPurpose {
    Access,
    ProfileCheck,
}

fn session_for_refresh(
    state: AuthState,
    purpose: RefreshPurpose,
) -> Result<AuthSession, AuthError> {
    match (state, purpose) {
        (AuthState::LoggedIn(session), _)
        | (AuthState::Banned(session), RefreshPurpose::ProfileCheck) => Ok(session),
        (AuthState::Banned(session), RefreshPurpose::Access) => Err(AuthError::UserBanned(
            AuthManager::ban_suffix(&session.user.banned_reason),
        )),
        _ => Err(AuthError::NotAuthenticated),
    }
}

#[derive(Default)]
struct RefreshBackoff {
    deadline: Option<Instant>,
    rate_limited: bool,
}

impl RefreshBackoff {
    fn waiting_result(&self, now: Instant, expired: bool) -> Option<Result<(), AuthError>> {
        let remaining = self.deadline?.checked_duration_since(now)?;
        if remaining.is_zero() {
            return None;
        }
        if !expired {
            return Some(Ok(()));
        }
        let wait = remaining.as_secs().max(1);
        Some(Err(if self.rate_limited {
            AuthError::RateLimited(wait)
        } else {
            AuthError::NetworkError(format!(
                "Could not refresh your login. Try again in {wait} seconds."
            ))
        }))
    }
}

/// Authentication manager
pub struct AuthManager {
    state: Arc<Mutex<AuthState>>,
    storage: SecureStorage,
    client: AuthClient,
    /// Active OAuth server (if awaiting callback)
    oauth_server: Arc<Mutex<Option<OAuthServer>>>,
    /// Suppress repeated refreshes after throttling or temporary failures.
    ///
    /// Handling the 429 once it arrives is not enough: `refresh_if_needed` is
    /// called ahead of API work, so an expired token means every subsequent
    /// call tries again and adds to the very throttle it is waiting on. This
    /// stops the request being sent at all until the server's `Retry-After`
    /// has passed.
    refresh_backoff: Arc<Mutex<RefreshBackoff>>,
}

/// Read-only account state, independent of an owner's async operation lock.
/// This cannot start API requests or change a session.
#[derive(Clone)]
pub struct AuthStateReader(Arc<Mutex<AuthState>>);

impl AuthStateReader {
    pub fn get_state(&self) -> AuthState {
        self.0.lock().clone()
    }
}

fn exhausted_refresh_result(expired: bool, last_error: AuthError) -> Result<(), AuthError> {
    // Access-token expiry and temporary refresh failures do not revoke the
    // saved refresh token. Keep it so a later request can recover online.
    if expired { Err(last_error) } else { Ok(()) }
}

fn persist_new_session(
    state: &Mutex<AuthState>,
    session: AuthSession,
    persist: impl FnOnce(&AuthSession) -> Result<(), AuthError>,
) -> Result<(), AuthError> {
    if let Err(error) = persist(&session) {
        // Both password and browser sign-in enter LoggingIn before saving.
        // A disk/credential-store failure must end that pending state too.
        *state.lock() = AuthState::Error(error.to_string());
        return Err(error);
    }
    *state.lock() = if session.user.is_banned {
        AuthState::Banned(session)
    } else {
        AuthState::LoggedIn(session)
    };
    Ok(())
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
                info!("  User ID: {}", session.user.id);
                info!("  Token length: {} chars", session.access_token.len());
                info!(
                    "  Refresh token length: {} chars",
                    session.refresh_token.len()
                );
                info!("  Expires at: {}", session.expires_at);
                info!("  Is expired: {}", session.is_expired());
                info!("  Expires soon: {}", session.expires_soon());
                if session.is_expired() {
                    info!("Session is expired but will be refreshed on first API call.");
                }
                info!("========================================");
                if session.user.is_banned {
                    AuthState::Banned(session)
                } else {
                    AuthState::LoggedIn(session)
                }
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

        info!(
            "AuthManager initialized with state: {:?}",
            match &initial_state {
                AuthState::LoggedIn(_) => "LoggedIn",
                AuthState::Banned(_) => "Banned",
                AuthState::LoggedOut => "LoggedOut",
                AuthState::LoggingIn => "LoggingIn",
                AuthState::AwaitingOAuthCallback(_) => "AwaitingOAuthCallback",
                AuthState::Error(_) => "Error",
            }
        );

        Ok(Self {
            state: Arc::new(Mutex::new(initial_state)),
            storage,
            client,
            oauth_server: Arc::new(Mutex::new(None)),
            refresh_backoff: Arc::new(Mutex::new(RefreshBackoff::default())),
        })
    }

    /// Get the current auth state
    pub fn get_state(&self) -> AuthState {
        self.state.lock().clone()
    }

    pub fn state_reader(&self) -> AuthStateReader {
        AuthStateReader(self.state.clone())
    }

    /// Check if user is logged in
    pub fn is_logged_in(&self) -> bool {
        matches!(self.get_state(), AuthState::LoggedIn(_))
    }

    /// Get the current user info if logged in
    pub fn get_user(&self) -> Option<UserInfo> {
        match self.get_state() {
            AuthState::LoggedIn(session) | AuthState::Banned(session) => Some(session.user),
            _ => None,
        }
    }

    pub fn mark_current_session_banned(&self, reason_suffix: &str) -> Result<(), AuthError> {
        let mut session = match self.get_state() {
            AuthState::LoggedIn(session) | AuthState::Banned(session) => session,
            _ => return Err(AuthError::NotAuthenticated),
        };

        session.user.is_banned = true;
        session.user.banned_reason = Self::reason_from_ban_suffix(reason_suffix);

        if let Err(e) = self.storage.store_session(&session) {
            warn!("Failed to store banned session: {}", e);
        }
        self.set_session_state(session);
        Ok(())
    }

    fn ban_suffix(reason: &Option<String>) -> String {
        reason
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(|value| format!(": {}", value))
            .unwrap_or_default()
    }

    fn reason_from_ban_suffix(suffix: &str) -> Option<String> {
        let trimmed = suffix.strip_prefix(':').unwrap_or(suffix).trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    fn session_from_profile(mut session: AuthSession, profile: UserProfileResponse) -> AuthSession {
        session.user.is_tester = profile.is_tester;
        session.user.is_banned = profile.is_banned;
        session.user.banned_reason = profile.banned_reason;
        session.user.banned_at = profile.banned_at;
        session
    }

    fn fallback_profile(user_id: String) -> UserProfileResponse {
        UserProfileResponse {
            id: user_id,
            full_name: None,
            username: None,
            is_admin: false,
            is_tester: false,
            is_banned: false,
            banned_reason: None,
            banned_at: None,
        }
    }

    fn session_from_auth_response(
        auth_response: SupabaseAuthResponse,
        fallback_email: String,
        is_tester: bool,
        is_banned: bool,
        banned_reason: Option<String>,
        banned_at: Option<String>,
    ) -> AuthSession {
        AuthSession {
            access_token: auth_response.access_token,
            refresh_token: auth_response.refresh_token,
            expires_at: Utc::now() + Duration::seconds(auth_response.expires_in),
            user: UserInfo {
                id: auth_response.user.id,
                email: auth_response.user.email.unwrap_or(fallback_email),
                is_tester,
                is_banned,
                banned_reason,
                banned_at,
            },
        }
    }

    fn store_and_set_session_state(&self, session: AuthSession) -> Result<(), AuthError> {
        persist_new_session(&self.state, session, |session| {
            self.storage.store_session(session)
        })
    }

    fn set_session_state(&self, session: AuthSession) {
        let mut state = self.state.lock();
        if session.user.is_banned {
            *state = AuthState::Banned(session);
        } else {
            *state = AuthState::LoggedIn(session);
        }
    }

    /// Sign in with email and password
    pub async fn sign_in(&self, email: &str, password: &str) -> Result<(), AuthError> {
        info!("Signing in user");

        // Set state to logging in
        {
            let mut state = self.state.lock();
            *state = AuthState::LoggingIn;
        }

        // Call Supabase auth
        match self.client.sign_in_with_password(email, password).await {
            Ok(response) => {
                let mut user_info = UserInfo {
                    id: response.user.id.clone(),
                    email: response
                        .user
                        .email
                        .clone()
                        .unwrap_or_else(|| email.to_string()),
                    is_tester: false,
                    is_banned: false,
                    banned_reason: None,
                    banned_at: None,
                };

                // Fetch user profile to get tester and ban status.
                match self.client.fetch_user_profile(&response.access_token).await {
                    Ok(profile) => {
                        user_info.is_tester = profile.is_tester;
                        user_info.is_banned = profile.is_banned;
                        user_info.banned_reason = profile.banned_reason;
                        user_info.banned_at = profile.banned_at;
                        info!(
                            "User profile fetched: is_tester={}, is_banned={}",
                            user_info.is_tester, user_info.is_banned
                        );
                    }
                    Err(AuthError::UserBanned(reason)) => {
                        let session = Self::session_from_auth_response(
                            response,
                            email.to_string(),
                            false,
                            true,
                            Self::reason_from_ban_suffix(&reason),
                            None,
                        );
                        if let Err(e) = self.storage.store_session(&session) {
                            warn!("Failed to store banned password session: {}", e);
                        }
                        self.set_session_state(session);
                        return Err(AuthError::UserBanned(reason));
                    }
                    Err(e) => {
                        warn!(
                            "Failed to fetch user profile during sign-in; continuing with default profile fields: {}",
                            e
                        );
                    }
                }

                let session = AuthSession {
                    access_token: response.access_token,
                    refresh_token: response.refresh_token,
                    expires_at: Utc::now() + Duration::seconds(response.expires_in),
                    user: user_info,
                };

                self.store_and_set_session_state(session.clone())?;

                if session.user.is_banned {
                    warn!("Sign in completed for banned user {}", session.user.id);
                    Err(AuthError::UserBanned(Self::ban_suffix(
                        &session.user.banned_reason,
                    )))
                } else {
                    info!("Sign in successful!");
                    Ok(())
                }
            }
            Err(e) => {
                error!("Sign in failed: {}", e);
                // Reset state to logged out with error
                {
                    let mut state = self.state.lock();
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
        self.refresh_session_if_needed(RefreshPurpose::Access).await
    }

    async fn refresh_session_if_needed(&self, purpose: RefreshPurpose) -> Result<(), AuthError> {
        let session = session_for_refresh(self.get_state(), purpose)?;

        // Check if refresh is needed (expired OR expiring soon)
        let needs_refresh = session.is_expired() || session.expires_soon();
        if !needs_refresh {
            debug!("Token still valid, no refresh needed");
            return Ok(());
        }

        // Still inside the window the server asked us to wait out. Sending now
        // would only deepen the throttle, and a 429 says nothing about whether
        // the session is still valid — so an unexpired token simply carries on.
        if let Some(result) = self
            .refresh_backoff
            .lock()
            .waiting_result(Instant::now(), session.is_expired())
        {
            return result;
        }

        if session.is_expired() {
            info!("Token expired, attempting refresh...");
        } else {
            info!("Token expiring soon, refreshing proactively...");
        }

        // Try to refresh with retries
        let mut last_error = AuthError::NetworkError("Could not refresh your session.".into());
        for attempt in 1..=MAX_REFRESH_RETRIES {
            match self.try_refresh_token(&session).await {
                Ok(new_session) => {
                    // Store and update state
                    if let Err(e) = self.storage.store_session(&new_session) {
                        warn!("Failed to store refreshed session: {}", e);
                        // Continue anyway - session is valid in memory
                    }

                    // Reset refresh failure count on success
                    *self.refresh_backoff.lock() = RefreshBackoff::default();

                    {
                        let mut state = self.state.lock();
                        if new_session.user.is_banned {
                            let reason = new_session.user.banned_reason.clone();
                            *state = AuthState::Banned(new_session);
                            warn!("Token refresh detected banned account");
                            return Err(AuthError::UserBanned(Self::ban_suffix(&reason)));
                        }
                        *state = AuthState::LoggedIn(new_session);
                    }

                    info!("Token refreshed successfully on attempt {}", attempt);
                    return Ok(());
                }
                Err(e) => {
                    // Permanent error: token revoked/rotated — retrying won't help
                    if matches!(e, AuthError::RefreshTokenInvalid) {
                        warn!("Refresh token is permanently invalid — forcing re-login");
                        let _ = self.force_logout();
                        return Err(e);
                    }
                    if let AuthError::UserBanned(reason) = &e {
                        // A ban can now come directly from the refresh API,
                        // before try_refresh_token reaches the profile lookup.
                        let _ = self.mark_current_session_banned(reason);
                        return Err(e);
                    }
                    if matches!(e, AuthError::UpdateRequired(_)) {
                        return Err(e);
                    }

                    // Throttled. Honor the server's delay without immediate
                    // retries or treating the credentials as revoked.
                    if let AuthError::RateLimited(retry_after) = e {
                        warn!(
                            "Token refresh rate limited; suppressing refreshes for {}s",
                            retry_after
                        );
                        *self.refresh_backoff.lock() = RefreshBackoff {
                            deadline: Instant::now()
                                .checked_add(StdDuration::from_secs(retry_after)),
                            rate_limited: true,
                        };

                        return if session.is_expired() {
                            Err(AuthError::RateLimited(retry_after))
                        } else {
                            Ok(())
                        };
                    }

                    warn!("Token refresh attempt {} failed: {}", attempt, e);
                    last_error = e;

                    // Wait before retry (exponential backoff: 1s, 2s, 4s)
                    if attempt < MAX_REFRESH_RETRIES {
                        let delay = StdDuration::from_secs(1 << (attempt - 1));
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        warn!(
            "Token refresh failed after {} attempts; keeping the saved session",
            MAX_REFRESH_RETRIES
        );

        *self.refresh_backoff.lock() = RefreshBackoff {
            deadline: Some(Instant::now() + TRANSIENT_REFRESH_BACKOFF),
            rate_limited: false,
        };
        exhausted_refresh_result(session.is_expired(), last_error)
    }

    /// Attempt a single token refresh
    async fn try_refresh_token(&self, session: &AuthSession) -> Result<AuthSession, AuthError> {
        let refresh_response = self.client.refresh_token(&session.refresh_token).await?;

        // Re-fetch profile status on refresh (in case admin changed tester or ban status)
        let profile = match self
            .client
            .fetch_user_profile(&refresh_response.access_token)
            .await
        {
            Ok(profile) => profile,
            Err(AuthError::UserBanned(reason)) => {
                let banned_session = Self::session_from_auth_response(
                    refresh_response,
                    session.user.email.clone(),
                    session.user.is_tester,
                    true,
                    Self::reason_from_ban_suffix(&reason),
                    session.user.banned_at.clone(),
                );
                if let Err(e) = self.storage.store_session(&banned_session) {
                    warn!("Failed to store banned refresh session: {}", e);
                }
                self.set_session_state(banned_session);
                return Err(AuthError::UserBanned(reason));
            }
            Err(e) => {
                debug!(
                    "Failed to fetch profile on refresh (keeping old value): {}",
                    e
                );
                UserProfileResponse {
                    id: session.user.id.clone(),
                    full_name: None,
                    username: None,
                    is_admin: false,
                    is_tester: session.user.is_tester,
                    is_banned: session.user.is_banned,
                    banned_reason: session.user.banned_reason.clone(),
                    banned_at: session.user.banned_at.clone(),
                }
            }
        };

        Ok(Self::session_from_auth_response(
            refresh_response,
            session.user.email.clone(),
            profile.is_tester,
            profile.is_banned,
            profile.banned_reason,
            profile.banned_at,
        ))
    }

    /// Re-fetch the user profile and update the stored session
    ///
    /// Call this on app startup to pick up changes made via the admin panel
    /// (e.g., tester access granted/revoked) without requiring a full re-login.
    pub async fn refresh_profile(&self) -> Result<(), AuthError> {
        if !matches!(
            self.get_state(),
            AuthState::LoggedIn(_) | AuthState::Banned(_)
        ) {
            return Ok(());
        }

        // The stored access token is routinely already expired by the time this
        // runs at startup, and fetching the profile with it just answers 401. So
        // the ban and tester check silently failed on exactly the launches where
        // it matters, while leaving an alarming error in the log. Refresh first
        // and use the token that comes back.
        //
        // Banned sessions may check their profile, but must not obtain an
        // ordinary access token or become LoggedIn just to make this request.
        // Only a successful server response can clear the saved ban. Expired
        // sessions still follow the existing refresh/revocation/backoff rules.
        self.refresh_session_if_needed(RefreshPurpose::ProfileCheck)
            .await?;

        let session = match self.get_state() {
            AuthState::LoggedIn(session) | AuthState::Banned(session) => session,
            _ => return Ok(()),
        };

        let profile = match self.client.fetch_user_profile(&session.access_token).await {
            Ok(profile) => profile,
            Err(AuthError::UserBanned(reason)) => {
                let mut banned_session = session;
                banned_session.user.is_banned = true;
                banned_session.user.banned_reason = Self::reason_from_ban_suffix(&reason);
                if let Err(e) = self.storage.store_session(&banned_session) {
                    warn!("Failed to store banned profile session: {}", e);
                }
                self.set_session_state(banned_session);
                return Err(AuthError::UserBanned(reason));
            }
            Err(err) => return Err(err),
        };
        info!(
            "Profile refreshed on startup: is_tester={}, is_banned={}",
            profile.is_tester, profile.is_banned
        );

        if profile.is_tester != session.user.is_tester
            || profile.is_banned != session.user.is_banned
            || profile.banned_reason != session.user.banned_reason
            || profile.banned_at != session.user.banned_at
        {
            info!(
                "Profile status changed: tester {} -> {}, banned {} -> {}",
                session.user.is_tester,
                profile.is_tester,
                session.user.is_banned,
                profile.is_banned
            );
            let updated_session = Self::session_from_profile(session, profile);
            if let Err(e) = self.storage.store_session(&updated_session) {
                warn!("Failed to store refreshed profile session: {}", e);
            }
            self.set_session_state(updated_session);
        }

        Ok(())
    }

    /// Get a valid access token, refreshing if needed
    pub async fn get_access_token(&self) -> Result<String, AuthError> {
        self.refresh_if_needed().await?;

        match self.get_state() {
            AuthState::LoggedIn(session) => Ok(session.access_token),
            AuthState::Banned(session) => Err(AuthError::UserBanned(Self::ban_suffix(
                &session.user.banned_reason,
            ))),
            _ => Err(AuthError::NotAuthenticated),
        }
    }

    /// Log out and clear stored credentials
    pub fn logout(&self) -> Result<(), AuthError> {
        info!("Logging out");

        self.storage.clear_session()?;

        {
            let mut state = self.state.lock();
            *state = AuthState::LoggedOut;
        }

        info!("Logged out successfully");
        Ok(())
    }

    /// Force logout due to invalid session (non-fatal on storage errors)
    fn force_logout(&self) -> Result<(), AuthError> {
        info!("Force logout: clearing invalid session");
        if let Err(e) = self.storage.clear_session() {
            warn!("Failed to clear session during force logout: {}", e);
        }
        {
            let mut state = self.state.lock();
            *state = AuthState::LoggedOut;
        }
        Ok(())
    }

    /// Cancel an in-flight login attempt regardless of which flow we're in.
    /// Stops any running OAuth callback server so the next login can rebind
    /// the localhost port.
    pub fn cancel_login(&self) {
        info!("Cancelling login");
        let was_awaiting_oauth = matches!(*self.state.lock(), AuthState::AwaitingOAuthCallback(_));
        if was_awaiting_oauth {
            self.stop_oauth_server();
        }
        let mut state = self.state.lock();
        *state = AuthState::LoggedOut;
    }

    /// Cancel only the OAuth callback wait without touching an already
    /// authenticated session.
    pub fn cancel_oauth(&self) {
        info!("Cancelling OAuth flow");
        let was_awaiting_oauth = matches!(*self.state.lock(), AuthState::AwaitingOAuthCallback(_));
        if was_awaiting_oauth {
            self.stop_oauth_server();
            let mut state = self.state.lock();
            if matches!(*state, AuthState::AwaitingOAuthCallback(_)) {
                *state = AuthState::LoggedOut;
            }
        }
    }

    /// Clear error state
    pub fn clear_error(&self) {
        let mut state = self.state.lock();
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
            let mut server_guard = self.oauth_server.lock();
            if let Some(mut server) = server_guard.take() {
                info!("Stopping previous OAuth server");
                server.stop();
            }
        }

        // Bind the listener to this attempt before the browser can reach it.
        let state: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        // Start the localhost OAuth server
        let oauth_server = match OAuthServer::start(&state) {
            Ok(server) => server,
            Err(e) => {
                error!("Failed to start OAuth server: {}", e);
                return Err(AuthError::ApiError(format!(
                    "Failed to start OAuth server: {}",
                    e
                )));
            }
        };

        let port = oauth_server.port();
        info!("OAuth server started on port {}", port);

        // Build the OAuth URL with the redirect port
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("desktop", "true")
            .append_pair("state", &state)
            .append_pair("provider", "google")
            .append_pair("redirect_port", &port.to_string())
            .finish();
        let oauth_url = format!(
            "{}{}?{}",
            crate::auth::http_client::current_api_base(),
            OAUTH_LOGIN_PATH,
            query
        );

        // Destination only. The query carries `state`, which binds the browser
        // session to this exchange, and users send these log files to support
        // as a matter of routine.
        info!(
            "Opening browser to: {}{} (query omitted)",
            crate::auth::http_client::current_api_base(),
            OAUTH_LOGIN_PATH
        );

        // Open the browser
        crate::utils::try_open_url(&oauth_url).map_err(AuthError::ApiError)?;

        // Store the OAuth server
        {
            let mut server_guard = self.oauth_server.lock();
            *server_guard = Some(oauth_server);
        }

        // Create the pending state
        let pending = OAuthPendingState {
            state: state.clone(),
            started_at: Utc::now(),
        };

        // Set state to awaiting OAuth callback
        {
            let mut auth_state = self.state.lock();
            *auth_state = AuthState::AwaitingOAuthCallback(pending);
        }

        info!(
            "OAuth flow started, waiting for localhost callback with state: {}...",
            &state[..8]
        );
        Ok(state)
    }

    /// Poll for OAuth callback (non-blocking)
    ///
    /// Call this periodically to check if the OAuth callback has been received.
    /// Returns Some(callback_data) if callback received, None otherwise.
    pub fn poll_oauth_callback(&self) -> Option<super::oauth_server::OAuthCallbackData> {
        let server_guard = self.oauth_server.lock();
        if let Some(ref server) = *server_guard {
            server.try_recv_callback()
        } else {
            None
        }
    }

    /// Get the OAuth server port (if active)
    pub fn get_oauth_port(&self) -> Option<u16> {
        let server_guard = self.oauth_server.lock();
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
        debug!("Completing OAuth callback (credentials omitted)");

        // Get expected state from memory
        let expected_state = {
            let state = self.state.lock();
            match &*state {
                AuthState::AwaitingOAuthCallback(pending) => {
                    // Check if the OAuth flow has expired (10 minutes)
                    if Utc::now() - pending.started_at > Duration::minutes(10) {
                        return Err(AuthError::ApiError(
                            "OAuth flow expired. Please try again.".to_string(),
                        ));
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
                return Err(AuthError::ApiError(
                    "Not waiting for OAuth callback. Please start sign-in again.".to_string(),
                ));
            }
        };

        if callback_state != expected_state {
            error!("OAuth callback state did not match the pending sign-in");
            // Reset state
            {
                let mut state = self.state.lock();
                *state = AuthState::Error(
                    "Security error: state mismatch. Please try again.".to_string(),
                );
            }
            // Stop OAuth server
            self.stop_oauth_server();
            return Err(AuthError::ApiError(
                "Security error: state mismatch".to_string(),
            ));
        }

        // Stop the OAuth server now that we've received the callback
        self.stop_oauth_server();

        // Set state to logging in
        {
            let mut state = self.state.lock();
            *state = AuthState::LoggingIn;
        }

        // Exchange the token for a magic link
        let exchange_response = match self
            .client
            .exchange_oauth_token(exchange_token, callback_state)
            .await
        {
            Ok(response) => response,
            Err(e) => {
                error!("Failed to exchange OAuth token: {}", e);
                {
                    let mut state = self.state.lock();
                    *state = AuthState::Error(e.to_string());
                }
                return Err(e);
            }
        };

        info!("Exchanged OAuth code for magic link");

        // New web builds return a ready session so desktop does not need to
        // contact auth.swifttunnel.net, which some networks block.
        let auth_response = if let (Some(access_token), Some(refresh_token)) = (
            exchange_response.access_token.as_ref(),
            exchange_response.refresh_token.as_ref(),
        ) {
            info!("Using server-verified desktop OAuth session");
            SupabaseAuthResponse {
                access_token: access_token.clone(),
                refresh_token: refresh_token.clone(),
                expires_in: exchange_response.expires_in.unwrap_or(3600),
                expires_at: exchange_response.expires_at,
                token_type: exchange_response
                    .session_token_type
                    .clone()
                    .unwrap_or_else(|| "bearer".to_string()),
                user: SupabaseUser {
                    id: exchange_response.user_id.clone(),
                    email: Some(exchange_response.email.clone()),
                },
            }
        } else {
            match self
                .client
                .verify_magic_link(&exchange_response.token)
                .await
            {
                Ok(response) => response,
                Err(e) => {
                    error!("Failed to verify magic link: {}", e);
                    {
                        let mut state = self.state.lock();
                        *state = AuthState::Error(e.to_string());
                    }
                    return Err(e);
                }
            }
        };

        // Fetch user profile to get tester and ban status
        let profile = match self
            .client
            .fetch_user_profile(&auth_response.access_token)
            .await
        {
            Ok(profile) => {
                info!(
                    "User profile fetched after OAuth: is_tester={}, is_banned={}",
                    profile.is_tester, profile.is_banned
                );
                profile
            }
            Err(AuthError::UserBanned(reason)) => {
                let session = Self::session_from_auth_response(
                    auth_response,
                    exchange_response.email,
                    false,
                    true,
                    Self::reason_from_ban_suffix(&reason),
                    None,
                );
                if let Err(e) = self.storage.store_session(&session) {
                    warn!("Failed to store banned OAuth session: {}", e);
                }
                self.set_session_state(session);
                return Err(AuthError::UserBanned(reason));
            }
            Err(e) => {
                warn!(
                    "Failed to fetch user profile after OAuth; continuing with default profile fields: {}",
                    e
                );
                Self::fallback_profile(auth_response.user.id.clone())
            }
        };

        // Create session
        let session = Self::session_from_auth_response(
            auth_response,
            exchange_response.email,
            profile.is_tester,
            profile.is_banned,
            profile.banned_reason,
            profile.banned_at,
        );

        self.store_and_set_session_state(session.clone())?;

        if session.user.is_banned {
            warn!("Google OAuth completed for banned user {}", session.user.id);
        } else {
            info!("Google OAuth sign-in successful!");
        }
        Ok(())
    }

    /// Stop the OAuth server if it's running
    fn stop_oauth_server(&self) {
        let mut server_guard = self.oauth_server.lock();
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

#[cfg(test)]
mod tests {
    use super::AuthManager;
    use crate::auth::types::{SupabaseAuthResponse, SupabaseUser};
    use url::form_urlencoded;

    #[tokio::test]
    async fn a_failed_ban_recheck_reaches_transport_without_unlocking_account_access() {
        use super::*;
        let storage_path = std::env::temp_dir().join(format!(
            "swifttunnel-ban-recheck-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        assert!(!storage_path.exists());
        let mut session = AuthManager::session_from_auth_response(
            SupabaseAuthResponse {
                access_token: "fixture-access".into(),
                refresh_token: "fixture-refresh".into(),
                expires_in: 3600,
                expires_at: None,
                token_type: "bearer".into(),
                user: SupabaseUser {
                    id: "fixture-user".into(),
                    email: None,
                },
            },
            "fixture@example.invalid".into(),
            false,
            true,
            Some("fixture reason".into()),
            None,
        );
        session.expires_at = Utc::now() + Duration::hours(1);
        let original = AuthState::Banned(session);
        let manager = AuthManager {
            state: Arc::new(Mutex::new(original.clone())),
            storage: SecureStorage::with_test_directory(storage_path.clone()),
            client: AuthClient::unavailable_for_test(),
            oauth_server: Arc::new(Mutex::new(None)),
            refresh_backoff: Arc::new(Mutex::new(RefreshBackoff::default())),
        };
        assert!(matches!(
            manager.get_access_token().await,
            Err(AuthError::UserBanned(_))
        ));
        // A working recheck reaches the profile transport. The fixture never
        // opens a socket or uses the machine's credential store.
        assert!(matches!(
            manager.refresh_profile().await,
            Err(AuthError::NetworkError(_))
        ));
        assert_eq!(manager.get_state(), original);
        assert!(matches!(
            manager.get_access_token().await,
            Err(AuthError::UserBanned(_))
        ));
        let AuthState::Banned(mut expired) = manager.get_state() else {
            panic!("failed recheck must preserve the ban");
        };
        expired.expires_at = Utc::now() - Duration::seconds(1);
        *manager.state.lock() = AuthState::Banned(expired.clone());
        *manager.refresh_backoff.lock() = RefreshBackoff {
            deadline: Some(Instant::now() + StdDuration::from_secs(30)),
            rate_limited: true,
        };
        assert!(matches!(
            manager.refresh_profile().await,
            Err(AuthError::RateLimited(_))
        ));
        assert_eq!(manager.get_state(), AuthState::Banned(expired));
        assert!(
            !storage_path.exists(),
            "no credential file should be written after failure"
        );
        // Holding the manager for an account operation must not delay status
        // reads. The reader observes subsequent changes from the same manager.
        let reader = manager.state_reader();
        let operations = tokio::sync::Mutex::new(manager);
        let account_operation = operations.lock().await;
        assert!(matches!(reader.get_state(), AuthState::Banned(_)));
        account_operation.cancel_login();
        assert_eq!(reader.get_state(), AuthState::LoggedOut);
    }

    #[test]
    fn a_saved_ban_allows_only_a_profile_check_until_the_server_clears_it() {
        use super::{AuthError, AuthSession, AuthState, RefreshPurpose, session_for_refresh};
        use crate::auth::{http_client::UserProfileResponse, types::UserInfo};
        let session = AuthSession {
            access_token: "fixture-access".into(),
            refresh_token: "fixture-refresh".into(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            user: UserInfo {
                id: "fixture-user".into(),
                email: "fixture@example.invalid".into(),
                is_tester: false,
                is_banned: true,
                banned_reason: Some("fixture reason".into()),
                banned_at: Some("2026-10-25T00:00:00Z".into()),
            },
        };
        let state = AuthState::Banned(session.clone());
        assert!(matches!(
            session_for_refresh(state.clone(), RefreshPurpose::Access),
            Err(AuthError::UserBanned(reason)) if reason == ": fixture reason"
        ));
        let for_check = session_for_refresh(state.clone(), RefreshPurpose::ProfileCheck).unwrap();
        assert_eq!(for_check, session);
        // Obtaining the session for the status request never publishes access.
        assert!(matches!(state, AuthState::Banned(_)));
        assert!(matches!(
            session_for_refresh(state, RefreshPurpose::Access),
            Err(AuthError::UserBanned(_))
        ));

        let profile = UserProfileResponse {
            id: session.user.id.clone(),
            full_name: None,
            username: None,
            is_admin: false,
            is_tester: false,
            is_banned: false,
            banned_reason: None,
            banned_at: None,
        };
        let updated = AuthManager::session_from_profile(for_check, profile);
        assert!(!updated.user.is_banned);
        assert!(updated.user.banned_reason.is_none());
        assert!(updated.user.banned_at.is_none());
        assert!(session_for_refresh(AuthState::LoggedIn(updated), RefreshPurpose::Access).is_ok());

        for state in [
            AuthState::LoggedOut,
            AuthState::LoggingIn,
            AuthState::Error("fixture".into()),
            AuthState::AwaitingOAuthCallback(crate::auth::types::OAuthPendingState {
                state: "fixture".into(),
                started_at: chrono::Utc::now(),
            }),
        ] {
            for purpose in [RefreshPurpose::Access, RefreshPurpose::ProfileCheck] {
                assert!(matches!(
                    session_for_refresh(state.clone(), purpose),
                    Err(AuthError::NotAuthenticated)
                ));
            }
        }
    }

    #[test]
    fn failed_login_persistence_ends_logging_in_and_allows_a_later_retry() {
        use super::{AuthError, AuthState, Mutex, persist_new_session};
        let state = Mutex::new(AuthState::LoggingIn);
        let session = AuthManager::session_from_auth_response(
            SupabaseAuthResponse {
                access_token: "fixture-access".into(),
                refresh_token: "fixture-refresh".into(),
                expires_in: 3600,
                expires_at: None,
                token_type: "bearer".into(),
                user: SupabaseUser {
                    id: "fixture-user".into(),
                    email: None,
                },
            },
            "fixture@example.invalid".into(),
            false,
            false,
            None,
            None,
        );
        let failed = persist_new_session(&state, session.clone(), |_| {
            Err(AuthError::StorageError("fixture disk is full".into()))
        });
        assert!(matches!(failed, Err(AuthError::StorageError(_))));
        assert!(
            matches!(&*state.lock(), AuthState::Error(message) if message.contains("disk is full"))
        );

        *state.lock() = AuthState::LoggingIn;
        persist_new_session(&state, session.clone(), |_| Ok(())).unwrap();
        assert_eq!(*state.lock(), AuthState::LoggedIn(session.clone()));
        let mut banned = session;
        banned.user.is_banned = true;
        persist_new_session(&state, banned.clone(), |_| Ok(())).unwrap();
        assert_eq!(*state.lock(), AuthState::Banned(banned));
    }

    #[test]
    fn refresh_backoff_suppresses_requests_until_its_monotonic_deadline() {
        use super::{Instant, RefreshBackoff, StdDuration};
        use crate::auth::types::AuthError;
        let now = Instant::now();
        let deadline = now + StdDuration::from_secs(30);
        for rate_limited in [false, true] {
            let backoff = RefreshBackoff {
                deadline: Some(deadline),
                rate_limited,
            };
            assert!(matches!(backoff.waiting_result(now, false), Some(Ok(()))));
            let blocked = backoff.waiting_result(now, true);
            if rate_limited {
                assert!(matches!(blocked, Some(Err(AuthError::RateLimited(30)))));
            } else {
                assert!(matches!(blocked, Some(Err(AuthError::NetworkError(_)))));
            }
            assert!(backoff.waiting_result(deadline, true).is_none());
            assert!(
                backoff
                    .waiting_result(deadline + StdDuration::from_secs(1), true)
                    .is_none()
            );
        }
        assert!(
            RefreshBackoff::default()
                .waiting_result(now, true)
                .is_none()
        );
    }

    #[test]
    fn temporary_refresh_failures_never_become_revoked_credentials() {
        use super::exhausted_refresh_result;
        use crate::auth::types::AuthError;
        for detail in ["offline", "DNS lookup failed", "request timed out"] {
            assert!(
                exhausted_refresh_result(false, AuthError::NetworkError(detail.into())).is_ok()
            );
            assert!(matches!(
                exhausted_refresh_result(true, AuthError::NetworkError(detail.into())),
                Err(AuthError::NetworkError(message)) if message == detail
            ));
        }
    }

    #[test]
    fn expired_access_token_reports_the_server_failure_without_claiming_a_bad_login() {
        use crate::auth::types::AuthError;
        assert!(matches!(
            super::exhausted_refresh_result(true, AuthError::ApiError("service unavailable".into())),
            Err(AuthError::ApiError(message)) if message == "service unavailable"
        ));
    }

    #[test]
    fn test_form_urlencoded_round_trip_state() {
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("desktop", "true")
            .append_pair("state", "abc123XYZ_-.~")
            .append_pair("provider", "google")
            .append_pair("redirect_port", "17435")
            .finish();
        // url crate's form_urlencoded uses + for spaces and percent-encodes anything not unreserved
        assert!(query.contains("desktop=true"));
        assert!(query.contains("state=abc123XYZ_-.%7E"));
        assert!(query.contains("provider=google"));
        assert!(query.contains("redirect_port=17435"));
    }

    #[test]
    fn test_form_urlencoded_handles_reserved_chars() {
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("state", "hello world&foo=bar")
            .finish();
        // Spaces become +, & and = get percent-encoded
        assert_eq!(query, "state=hello+world%26foo%3Dbar");
    }

    #[test]
    fn ban_suffix_trims_empty_reasons() {
        assert_eq!(AuthManager::ban_suffix(&None), "");
        assert_eq!(AuthManager::ban_suffix(&Some("   ".to_string())), "");
        assert_eq!(
            AuthManager::ban_suffix(&Some("  chargeback  ".to_string())),
            ": chargeback"
        );
    }

    #[test]
    fn reason_from_ban_suffix_trims_display_prefix() {
        assert_eq!(AuthManager::reason_from_ban_suffix(""), None);
        assert_eq!(AuthManager::reason_from_ban_suffix(":   "), None);
        assert_eq!(
            AuthManager::reason_from_ban_suffix(": chargeback"),
            Some("chargeback".to_string())
        );
    }

    #[test]
    fn fallback_profile_is_not_banned_or_tester() {
        let profile = AuthManager::fallback_profile("user-1".to_string());
        assert_eq!(profile.id, "user-1");
        assert!(!profile.is_tester);
        assert!(!profile.is_banned);
        assert!(profile.banned_reason.is_none());
        assert!(profile.banned_at.is_none());
    }

    #[test]
    fn auth_response_session_preserves_ban_fields_and_fallback_email() {
        let response = SupabaseAuthResponse {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            expires_in: 3600,
            expires_at: None,
            token_type: "bearer".to_string(),
            user: SupabaseUser {
                id: "user-1".to_string(),
                email: None,
            },
        };

        let session = AuthManager::session_from_auth_response(
            response,
            "fallback@example.com".to_string(),
            true,
            true,
            Some("chargeback".to_string()),
            Some("2026-05-07T00:00:00.000Z".to_string()),
        );

        assert_eq!(session.user.email, "fallback@example.com");
        assert!(session.user.is_tester);
        assert!(session.user.is_banned);
        assert_eq!(session.user.banned_reason.as_deref(), Some("chargeback"));
        assert_eq!(
            session.user.banned_at.as_deref(),
            Some("2026-05-07T00:00:00.000Z")
        );
    }
}
