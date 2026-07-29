//! HTTP client for SwiftTunnel API

use super::device_identity::desktop_hwid;
use super::types::{
    AuthError, ExchangeTokenResponse, RelayTicketResponse, SupabaseAuthResponse, VpnConfig,
};
use log::{debug, error, info, warn};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::sync::OnceLock;

/// Response from the user profile API
#[derive(Debug, Clone, serde::Deserialize)]
pub struct UserProfileResponse {
    pub id: String,
    #[serde(default)]
    pub full_name: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default)]
    pub is_tester: bool,
    #[serde(default)]
    pub is_banned: bool,
    #[serde(default)]
    pub banned_reason: Option<String>,
    #[serde(default)]
    pub banned_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiErrorResponse {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    banned_reason: Option<String>,
    #[serde(default)]
    error: Option<String>,
    /// Human-readable text. Routes that put a machine code in `error` carry the
    /// sentence for the user here instead.
    #[serde(default)]
    message: Option<String>,
}

const API_BASE_URL: &str = "https://www.swifttunnel.net";
const SUPABASE_URL: &str = "https://ppwacjpkeonxdblwygqo.supabase.co";
const SUPABASE_ANON_KEY: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBwd2FjanBrZW9ueGRibHd5Z3FvIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODI4OTY1NTksImV4cCI6MjA5ODQ3MjU1OX0.WSRbDCg2NUJhZ4DiWh8PKbCKoi9oHO5td86HJFK7iBw";

/// The running app version, reported to the API in the `X-SwiftTunnel-Version`
/// header so the server can lock out builds pulled from old GitHub releases.
/// Set once at startup by the desktop shell via [`set_client_version`]; falls
/// back to this crate's version if never set (e.g. in tests).
static CLIENT_VERSION: OnceLock<String> = OnceLock::new();

/// Record the running app version. Call once at startup from the Tauri shell.
pub fn set_client_version(version: impl Into<String>) {
    let _ = CLIENT_VERSION.set(version.into());
}

fn client_version() -> &'static str {
    CLIENT_VERSION
        .get()
        .map(String::as_str)
        .unwrap_or(env!("CARGO_PKG_VERSION"))
}

/// Set the first time the server rejects this build as too old (old-build
/// lockout). Once set, the app shows the forced-update gate until the user
/// updates and restarts.
static UPDATE_REQUIRED_MESSAGE: OnceLock<String> = OnceLock::new();

/// The "please update" message if the server has locked this build out, else None.
pub fn update_required_message() -> Option<String> {
    UPDATE_REQUIRED_MESSAGE.get().cloned()
}

/// HTTP client for authentication API calls
pub struct AuthClient {
    client: Client,
    direct_client: Client,
    device_hwid: Option<String>,
}

fn build_http_client(use_system_proxy: bool) -> Client {
    let mut builder = Client::builder()
        // Real build version (set at startup) so server logs/WAF can tell
        // client versions apart instead of the old hardcoded "0.1.0".
        .user_agent(format!("SwiftTunnel-Desktop/{}", client_version()))
        .timeout(std::time::Duration::from_secs(30))
        .use_native_tls();

    if !use_system_proxy {
        builder = builder.no_proxy();
    }

    builder.build().expect("Failed to create HTTP client")
}

impl AuthClient {
    /// Create a new AuthClient
    pub fn new() -> Self {
        let client = build_http_client(true);
        let direct_client = build_http_client(false);

        Self {
            client,
            direct_client,
            device_hwid: desktop_hwid(),
        }
    }

    #[cfg(test)]
    fn with_device_hwid(device_hwid: Option<String>) -> Self {
        let client = build_http_client(true);
        let direct_client = build_http_client(false);

        Self {
            client,
            direct_client,
            device_hwid,
        }
    }

    fn add_common_headers(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        // Report the running build so the server can lock out old versions.
        let request = request.header("X-SwiftTunnel-Version", client_version());
        match &self.device_hwid {
            Some(hwid) => request.header("X-SwiftTunnel-HWID", hwid),
            None => request,
        }
    }

    async fn send_with_network_fallback<F>(
        &self,
        label: &str,
        build_request: F,
    ) -> Result<reqwest::Response, AuthError>
    where
        F: Fn(&Client) -> reqwest::RequestBuilder,
    {
        match build_request(&self.client).send().await {
            Ok(response) => Ok(response),
            Err(primary_error) => {
                warn!(
                    "{} request failed through the system network path: {}. Retrying direct.",
                    label, primary_error
                );

                build_request(&self.direct_client)
                    .send()
                    .await
                    .map_err(|direct_error| {
                        AuthError::NetworkError(format!(
                            "{}. Direct retry also failed: {}",
                            primary_error, direct_error
                        ))
                    })
            }
        }
    }

    fn exchange_oauth_payload(&self, exchange_token: &str, state: &str) -> serde_json::Value {
        let mut payload = json!({
            "exchange_token": exchange_token,
            "state": state,
        });
        if let Some(hwid) = &self.device_hwid {
            payload["device_hwid"] = json!(hwid);
        }
        payload
    }

    async fn parse_password_sign_in_response(
        &self,
        response: reqwest::Response,
    ) -> Result<SupabaseAuthResponse, AuthError> {
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Sign in failed: {} - {}", status, body);

            if let Some(error) = user_banned_error_from_body(&body) {
                return Err(error);
            }
            if body.contains("Invalid login credentials") {
                return Err(AuthError::ApiError("Invalid email or password".to_string()));
            }
            return Err(AuthError::ApiError(format!(
                "Sign in failed: {} - {}",
                status, body
            )));
        }

        response
            .json()
            .await
            .map_err(|e| AuthError::ApiError(format!("Failed to parse response: {}", e)))
    }

    async fn sign_in_with_password_via_desktop_api(
        &self,
        email: &str,
        password: &str,
    ) -> Result<SupabaseAuthResponse, AuthError> {
        let url = format!("{}/api/auth/desktop/password", API_BASE_URL);
        let response = self
            .send_with_network_fallback("desktop password sign in", |client| {
                self.add_common_headers(
                    client
                        .post(&url)
                        .header("Content-Type", "application/json")
                        .json(&json!({
                            "email": email,
                            "password": password,
                        })),
                )
            })
            .await?;

        self.parse_password_sign_in_response(response).await
    }

    async fn refresh_token_via_desktop_api(
        &self,
        refresh_token: &str,
    ) -> Result<SupabaseAuthResponse, AuthError> {
        let url = format!("{}/api/auth/desktop/refresh", API_BASE_URL);
        let response = self
            .send_with_network_fallback("desktop token refresh", |client| {
                self.add_common_headers(
                    client
                        .post(&url)
                        .header("Content-Type", "application/json")
                        .json(&json!({
                            "refresh_token": refresh_token,
                        })),
                )
            })
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Desktop token refresh failed: {} - {}", status, body);

            if let Some(error) = user_banned_error_from_body(&body) {
                return Err(error);
            }
            if is_refresh_token_permanently_invalid(&body) {
                return Err(AuthError::RefreshTokenInvalid);
            }

            return Err(AuthError::ApiError(format!(
                "Refresh failed: {} - {}",
                status, body
            )));
        }

        response
            .json()
            .await
            .map_err(|e| AuthError::ApiError(format!("Failed to parse response: {}", e)))
    }

    /// Sign in with email and password via Supabase
    pub async fn sign_in_with_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<SupabaseAuthResponse, AuthError> {
        debug!("Signing in user: {}", email);

        match self
            .sign_in_with_password_via_desktop_api(email, password)
            .await
        {
            Ok(data) => {
                info!("Sign in successful for user {}", data.user.id);
                return Ok(data);
            }
            Err(primary_error) => {
                warn!(
                    "Desktop API sign in failed; trying direct Supabase fallback: {}",
                    primary_error
                );
            }
        }

        let url = format!("{}/auth/v1/token?grant_type=password", SUPABASE_URL);

        let response = match self
            .send_with_network_fallback("sign in", |client| {
                client
                    .post(&url)
                    .header("apikey", SUPABASE_ANON_KEY)
                    .header("Content-Type", "application/json")
                    .json(&json!({
                        "email": email,
                        "password": password,
                    }))
            })
            .await
        {
            Ok(response) => response,
            Err(primary_error) => return Err(primary_error),
        };

        let data = self.parse_password_sign_in_response(response).await?;

        info!("Sign in successful for user {}", data.user.id);
        Ok(data)
    }

    /// Refresh the access token via Supabase
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<SupabaseAuthResponse, AuthError> {
        debug!("Refreshing token via Supabase");

        match self.refresh_token_via_desktop_api(refresh_token).await {
            Ok(data) => return Ok(data),
            Err(AuthError::RefreshTokenInvalid) => return Err(AuthError::RefreshTokenInvalid),
            Err(primary_error) => {
                warn!(
                    "Desktop API token refresh failed; trying direct Supabase fallback: {}",
                    primary_error
                );
            }
        }

        let url = format!("{}/auth/v1/token?grant_type=refresh_token", SUPABASE_URL);

        let response = match self
            .send_with_network_fallback("refresh token", |client| {
                client
                    .post(&url)
                    .header("apikey", SUPABASE_ANON_KEY)
                    .header("Content-Type", "application/json")
                    .json(&json!({
                        "refresh_token": refresh_token,
                    }))
            })
            .await
        {
            Ok(response) => response,
            Err(primary_error) => return Err(primary_error),
        };

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Refresh token failed: {} - {}", status, body);

            // Detect permanently invalid refresh tokens (revoked, rotated, expired)
            if is_refresh_token_permanently_invalid(&body) {
                return Err(AuthError::RefreshTokenInvalid);
            }

            return Err(AuthError::ApiError(format!(
                "Refresh failed: {} - {}",
                status, body
            )));
        }

        let data: SupabaseAuthResponse = response
            .json()
            .await
            .map_err(|e| AuthError::ApiError(format!("Failed to parse response: {}", e)))?;

        info!("Token refresh successful");
        Ok(data)
    }

    /// Fetch VPN configuration for a region
    pub async fn get_vpn_config(
        &self,
        access_token: &str,
        region: &str,
    ) -> Result<VpnConfig, AuthError> {
        let url = format!("{}/api/vpn/generate-config", API_BASE_URL);

        debug!("Fetching VPN config for region {}", region);

        let response = self
            .send_with_network_fallback("VPN config", |client| {
                self.add_common_headers(client.post(&url))
                    .header("Authorization", format!("Bearer {}", access_token))
                    .json(&json!({
                        "region": region,
                    }))
            })
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Get VPN config failed: {} - {}", status, body);
            if let Some(error) = update_required_error(status, &body) {
                return Err(error);
            }
            if let Some(error) = user_banned_error_from_body(&body) {
                return Err(error);
            }
            return Err(AuthError::ApiError(format!(
                "Config fetch failed: {} - {}",
                status, body
            )));
        }

        let data: VpnConfig = response
            .json()
            .await
            .map_err(|e| AuthError::ApiError(format!("Failed to parse config: {}", e)))?;

        info!("Got VPN config for region {}", region);
        Ok(data)
    }

    /// Tell the API this session is over so the free-tier counter is settled
    /// against time actually spent connected.
    ///
    /// Without this the server can only settle a session when the *next* ticket
    /// is requested, and at that point it cannot tell a 30-second session from
    /// a full ticket window — it sees a long gap and charges the whole TTL. A
    /// few short sessions would burn a large slice of the daily allowance for
    /// time the user never had.
    ///
    /// Best effort by design: the caller is already disconnecting, so a failure
    /// here is logged and swallowed rather than shown. The cost of a missed
    /// release is the old over-charge, never a broken disconnect.
    pub async fn release_relay_quota(&self, access_token: &str) -> Result<(), AuthError> {
        let url = format!("{}/api/vpn/relay-release", API_BASE_URL);

        let response = self
            .send_with_network_fallback("relay release", |client| {
                self.add_common_headers(client.post(&url))
                    .header("Authorization", format!("Bearer {}", access_token))
                    .header("Content-Type", "application/json")
                    .json(&json!({}))
            })
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AuthError::ApiError(format!(
                "Relay release failed: {} - {}",
                status, body
            )));
        }

        debug!("Relay quota released for the finished session");
        Ok(())
    }

    /// Fetch a short-lived relay auth ticket for a specific session/server pair.
    pub async fn get_relay_ticket(
        &self,
        access_token: &str,
        server_region: &str,
        session_id: &str,
    ) -> Result<RelayTicketResponse, AuthError> {
        let url = format!("{}/api/vpn/relay-ticket", API_BASE_URL);

        debug!(
            "Fetching relay ticket for region {} and session {}",
            server_region, session_id
        );

        let response = self
            .send_with_network_fallback("relay ticket", |client| {
                self.add_common_headers(client.post(&url))
                    .header("Authorization", format!("Bearer {}", access_token))
                    .header("Content-Type", "application/json")
                    .json(&json!({
                        "server_region": server_region,
                        "session_id": session_id,
                    }))
            })
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Relay ticket fetch failed: {} - {}", status, body);
            if let Some(error) = update_required_error(status, &body) {
                return Err(error);
            }
            if let Some(error) = user_banned_error_from_body(&body) {
                return Err(error);
            }
            if let Some(error) = free_tier_limit_error(status, &body) {
                return Err(error);
            }
            return Err(AuthError::ApiError(format!(
                "Relay ticket fetch failed: {} - {}",
                status, body
            )));
        }

        let data: RelayTicketResponse = response
            .json()
            .await
            .map_err(|e| AuthError::ApiError(format!("Failed to parse relay ticket: {}", e)))?;

        info!(
            "Received relay ticket (auth_required: {}, key_id: {}, preflight_mode: {:?}, queue_full_mode: {:?})",
            data.auth_required,
            data.key_id,
            data.preflight_mode(),
            data.queue_full_mode()
        );
        Ok(data)
    }

    /// Exchange OAuth token for magic link token (desktop OAuth flow)
    /// Called after receiving the callback from browser OAuth
    pub async fn exchange_oauth_token(
        &self,
        exchange_token: &str,
        state: &str,
    ) -> Result<ExchangeTokenResponse, AuthError> {
        let url = format!("{}/api/auth/desktop/exchange", API_BASE_URL);

        debug!("Exchanging OAuth token for session");

        let response = self
            .send_with_network_fallback("desktop auth exchange", |client| {
                self.add_common_headers(client.put(&url))
                    .header("Content-Type", "application/json")
                    .json(&self.exchange_oauth_payload(exchange_token, state))
            })
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Exchange token failed: {} - {}", status, body);

            if let Some(error) = user_banned_error_from_body(&body) {
                return Err(error);
            }
            if body.contains("Invalid exchange token") {
                return Err(AuthError::ApiError(
                    "Invalid or expired exchange token. Please try again.".to_string(),
                ));
            }
            if body.contains("Token already used") {
                return Err(AuthError::ApiError(
                    "This login link has already been used. Please try again.".to_string(),
                ));
            }
            if body.contains("Token expired") {
                return Err(AuthError::ApiError(
                    "Login link expired. Please try again.".to_string(),
                ));
            }

            return Err(AuthError::ApiError(format!(
                "Exchange failed: {} - {}",
                status, body
            )));
        }

        let data: ExchangeTokenResponse = response.json().await.map_err(|e| {
            AuthError::ApiError(format!("Failed to parse exchange response: {}", e))
        })?;

        info!("Successfully exchanged OAuth token");
        Ok(data)
    }

    /// Fetch user profile from SwiftTunnel API (includes tester status)
    pub async fn fetch_user_profile(
        &self,
        access_token: &str,
    ) -> Result<UserProfileResponse, AuthError> {
        let url = format!("{}/api/user/profile", API_BASE_URL);

        debug!("Fetching user profile");

        let response = self
            .send_with_network_fallback("user profile", |client| {
                self.add_common_headers(client.get(&url))
                    .header("Authorization", format!("Bearer {}", access_token))
            })
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Fetch user profile failed: {} - {}", status, body);
            if let Some(error) = update_required_error(status, &body) {
                return Err(error);
            }
            if let Some(error) = user_banned_error_from_body(&body) {
                return Err(error);
            }
            return Err(AuthError::ApiError(format!(
                "Profile fetch failed: {} - {}",
                status, body
            )));
        }

        let data: UserProfileResponse = response
            .json()
            .await
            .map_err(|e| AuthError::ApiError(format!("Failed to parse profile: {}", e)))?;

        info!("Fetched user profile (is_tester: {})", data.is_tester);
        Ok(data)
    }

    /// Verify magic link token with Supabase to get access/refresh tokens
    pub async fn verify_magic_link(
        &self,
        email: &str,
        token_hash: &str,
    ) -> Result<SupabaseAuthResponse, AuthError> {
        let url = format!("{}/auth/v1/verify", SUPABASE_URL);

        debug!(
            "Verifying magic link token for {} (token_hash: {}...)",
            email,
            &token_hash[..token_hash.len().min(8)]
        );

        let response = self
            .send_with_network_fallback("magic link verification", |client| {
                client
                    .post(&url)
                    .header("apikey", SUPABASE_ANON_KEY)
                    .header("Content-Type", "application/json")
                    .json(&json!({
                        "type": "magiclink",
                        "token_hash": token_hash,
                    }))
            })
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Verify magic link failed: {} - {}", status, body);

            if body.contains("Token has expired")
                || body.contains("token is expired")
                || body.contains("expired")
            {
                return Err(AuthError::ApiError(
                    "Login link has expired. Please try signing in again.".to_string(),
                ));
            }
            if body.contains("Invalid token")
                || body.contains("token is invalid")
                || body.contains("invalid")
            {
                return Err(AuthError::ApiError(
                    "Invalid login link. Please try signing in again.".to_string(),
                ));
            }
            if body.contains("already been used") || body.contains("used") {
                return Err(AuthError::ApiError(
                    "This login link was already used. Please try signing in again.".to_string(),
                ));
            }

            return Err(AuthError::ApiError(format!(
                "Verification failed ({}). Please try signing in again.",
                status
            )));
        }

        let data: SupabaseAuthResponse = response
            .json()
            .await
            .map_err(|e| AuthError::ApiError(format!("Failed to parse auth response: {}", e)))?;

        info!("Magic link verification successful");
        Ok(data)
    }
}

impl Default for AuthClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Classify a Supabase refresh-token error response body.
///
/// Returns `true` if the error indicates a permanently invalid refresh token
/// (revoked, rotated, or not found). These errors should NOT be retried.
pub(crate) fn is_refresh_token_permanently_invalid(body: &str) -> bool {
    body.contains("refresh_token_not_found")
        || body.contains("Invalid Refresh Token")
        || body.contains("refresh_token_already_used")
}

/// Detect a server "update required" (old-build lockout) response: HTTP 426, or
/// an explicit `{"code":"update_required"}` body. Returns the user-facing
/// message so the app can prompt an update instead of a raw API error.
fn update_required_error(status: reqwest::StatusCode, body: &str) -> Option<AuthError> {
    let parsed: Option<ApiErrorResponse> = serde_json::from_str(body).ok();
    let code_matches =
        parsed.as_ref().and_then(|p| p.code.as_deref()) == Some("update_required");
    if status.as_u16() != 426 && !code_matches {
        return None;
    }
    let message = parsed.and_then(|p| p.error).unwrap_or_else(|| {
        "This version of SwiftTunnel is no longer supported. Please update to continue."
            .to_string()
    });
    // Latch it so the app can show a forced-update gate even if this particular
    // request's error is otherwise swallowed upstream.
    let _ = UPDATE_REQUIRED_MESSAGE.set(message.clone());
    Some(AuthError::UpdateRequired(message))
}

fn user_banned_error_from_body(body: &str) -> Option<AuthError> {
    let parsed: ApiErrorResponse = serde_json::from_str(body).ok()?;
    if parsed.code.as_deref() != Some("user_banned") {
        return None;
    }

    Some(AuthError::UserBanned(ban_reason_suffix(
        parsed.banned_reason,
    )))
}

/// Detect the free-tier quota rejection. `/api/vpn/relay-ticket` answers 429
/// with `{"error":"free_tier_limit_reached","message":"..."}` — note the code
/// lands in `error`, not `code`, unlike the ban and update responses.
fn free_tier_limit_error(status: reqwest::StatusCode, body: &str) -> Option<AuthError> {
    if status.as_u16() != 429 {
        return None;
    }
    let parsed: ApiErrorResponse = serde_json::from_str(body).ok()?;
    if parsed.error.as_deref() != Some("free_tier_limit_reached") {
        return None;
    }
    Some(AuthError::FreeTierLimitReached(
        parsed.message.unwrap_or_else(|| {
            "You've used your free SwiftTunnel time for now. This limit is temporary."
                .to_string()
        }),
    ))
}

fn ban_reason_suffix(reason: Option<String>) -> String {
    reason
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| format!(": {}", value))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_refresh_token_not_found() {
        let body = r#"{"code":400,"error_code":"refresh_token_not_found","msg":"Invalid Refresh Token: Refresh Token Not Found"}"#;
        assert!(is_refresh_token_permanently_invalid(body));
    }

    #[test]
    fn test_detects_refresh_token_already_used() {
        let body = r#"{"code":400,"error_code":"refresh_token_already_used","msg":"Refresh token already used"}"#;
        assert!(is_refresh_token_permanently_invalid(body));
    }

    #[test]
    fn test_detects_invalid_refresh_token_message() {
        let body = "Invalid Refresh Token";
        assert!(is_refresh_token_permanently_invalid(body));
    }

    #[test]
    fn test_transient_errors_are_not_permanent() {
        assert!(!is_refresh_token_permanently_invalid(
            "Internal Server Error",
        ));
        assert!(!is_refresh_token_permanently_invalid("rate_limit_exceeded"));
        assert!(!is_refresh_token_permanently_invalid(""));
    }

    #[test]
    fn test_user_banned_error_uses_structured_code() {
        let body = r#"{"error":"User banned","code":"user_banned","banned_reason":"chargeback"}"#;

        let error = user_banned_error_from_body(body).unwrap();

        assert_eq!(error.to_string(), "Account banned: chargeback");
    }

    #[test]
    fn test_user_banned_error_ignores_incidental_text() {
        let body = r#"{"error":"user_banned appeared in a log line","code":"internal_error"}"#;

        assert!(user_banned_error_from_body(body).is_none());
    }

    #[test]
    fn exchange_oauth_payload_includes_hwid_when_available() {
        let client = AuthClient::with_device_hwid(Some("hwid:v1:abc".to_string()));

        let payload = client.exchange_oauth_payload("exchange", "state");

        assert_eq!(payload["exchange_token"], "exchange");
        assert_eq!(payload["state"], "state");
        assert_eq!(payload["device_hwid"], "hwid:v1:abc");
    }

    #[test]
    fn exchange_oauth_payload_omits_missing_hwid() {
        let client = AuthClient::with_device_hwid(None);

        let payload = client.exchange_oauth_payload("exchange", "state");

        assert!(payload.get("device_hwid").is_none());
    }

    #[test]
    fn free_tier_limit_detected_and_message_passed_through() {
        let err = free_tier_limit_error(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            r#"{"error":"free_tier_limit_reached","message":"You've used your 3 hours of free SwiftTunnel time.","limit_seconds":10800,"remaining_seconds":0,"temporary":true}"#,
        )
        .unwrap();
        assert!(matches!(err, AuthError::FreeTierLimitReached(_)));
        assert_eq!(
            err.to_string(),
            "You've used your 3 hours of free SwiftTunnel time."
        );
    }

    #[test]
    fn free_tier_limit_ignores_the_ip_rate_limiter() {
        // The same route answers 429 for per-IP flooding; that one *is* worth
        // retrying, so it must not be mistaken for a spent allowance.
        assert!(free_tier_limit_error(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            r#"{"error":"rate_limited"}"#,
        )
        .is_none());
    }

    #[test]
    fn update_required_detected_by_status_426() {
        let err = update_required_error(
            reqwest::StatusCode::from_u16(426).unwrap(),
            r#"{"error":"Please update.","code":"update_required","min_version":"2.6.0"}"#,
        )
        .unwrap();
        assert!(matches!(err, AuthError::UpdateRequired(_)));
        assert_eq!(err.to_string(), "Please update.");
    }

    #[test]
    fn update_required_detected_by_code_without_426() {
        let err = update_required_error(
            reqwest::StatusCode::FORBIDDEN,
            r#"{"error":"Old build.","code":"update_required"}"#,
        )
        .unwrap();
        assert_eq!(err.to_string(), "Old build.");
    }

    #[test]
    fn update_required_falls_back_to_default_message_on_bare_426() {
        let err = update_required_error(
            reqwest::StatusCode::from_u16(426).unwrap(),
            "upgrade required",
        )
        .unwrap();
        assert!(err.to_string().contains("no longer supported"));
    }

    #[test]
    fn non_update_errors_are_not_update_required() {
        assert!(
            update_required_error(
                reqwest::StatusCode::FORBIDDEN,
                r#"{"error":"User banned","code":"user_banned"}"#,
            )
            .is_none()
        );
    }
}
