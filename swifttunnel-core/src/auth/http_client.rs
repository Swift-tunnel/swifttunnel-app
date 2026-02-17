//! HTTP client for SwiftTunnel API

use super::types::{
    AuthError, ExchangeTokenResponse, RelayTicketResponse, SupabaseAuthResponse, VpnConfig,
};
use log::{debug, error, info};
use reqwest::Client;
use serde_json::json;

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
}

const API_BASE_URL: &str = "https://swifttunnel.net";
const SUPABASE_URL: &str = "https://auth.swifttunnel.net";
const SUPABASE_ANON_KEY: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InpvbnVnanZvcWtsdmdibmh4c2hnIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjUyNTU3ODksImV4cCI6MjA4MDgzMTc4OX0.Jmme0whahuX2KEmklBZQzCcJnsHJemyO8U9TdynbyNE";

/// HTTP client for authentication API calls
pub struct AuthClient {
    client: Client,
}

impl AuthClient {
    /// Create a new AuthClient
    pub fn new() -> Self {
        let client = Client::builder()
            .user_agent("SwiftTunnel-Desktop/0.1.0")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }

    /// Sign in with email and password via Supabase
    pub async fn sign_in_with_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<SupabaseAuthResponse, AuthError> {
        let url = format!("{}/auth/v1/token?grant_type=password", SUPABASE_URL);

        debug!("Signing in user: {}", email);

        let response = self
            .client
            .post(&url)
            .header("apikey", SUPABASE_ANON_KEY)
            .header("Content-Type", "application/json")
            .json(&json!({
                "email": email,
                "password": password,
            }))
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Sign in failed: {} - {}", status, body);

            // Parse error message from Supabase
            if body.contains("Invalid login credentials") {
                return Err(AuthError::ApiError("Invalid email or password".to_string()));
            }
            return Err(AuthError::ApiError(format!(
                "Sign in failed: {} - {}",
                status, body
            )));
        }

        let data: SupabaseAuthResponse = response
            .json()
            .await
            .map_err(|e| AuthError::ApiError(format!("Failed to parse response: {}", e)))?;

        info!("Sign in successful for user {}", data.user.id);
        Ok(data)
    }

    /// Refresh the access token via Supabase
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<SupabaseAuthResponse, AuthError> {
        let url = format!("{}/auth/v1/token?grant_type=refresh_token", SUPABASE_URL);

        debug!("Refreshing token via Supabase");

        let response = self
            .client
            .post(&url)
            .header("apikey", SUPABASE_ANON_KEY)
            .header("Content-Type", "application/json")
            .json(&json!({
                "refresh_token": refresh_token,
            }))
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(e.to_string()))?;

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
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&json!({
                "region": region,
            }))
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Get VPN config failed: {} - {}", status, body);
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
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .header("Content-Type", "application/json")
            .json(&json!({
                "server_region": server_region,
                "session_id": session_id,
            }))
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Relay ticket fetch failed: {} - {}", status, body);
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
            "Received relay ticket (auth_required: {}, key_id: {})",
            data.auth_required, data.key_id
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
            .client
            .put(&url)
            .header("Content-Type", "application/json")
            .json(&json!({
                "exchange_token": exchange_token,
                "state": state,
            }))
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Exchange token failed: {} - {}", status, body);

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
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Fetch user profile failed: {} - {}", status, body);
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
            .client
            .post(&url)
            .header("apikey", SUPABASE_ANON_KEY)
            .header("Content-Type", "application/json")
            .json(&json!({
                "type": "magiclink",
                "token_hash": token_hash,
            }))
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(e.to_string()))?;

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
}
