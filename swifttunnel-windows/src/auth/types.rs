//! Authentication types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Authentication state
#[derive(Debug, Clone, PartialEq)]
pub enum AuthState {
    /// Not logged in
    LoggedOut,
    /// Login in progress (email/password)
    LoggingIn,
    /// Waiting for OAuth callback from browser
    AwaitingOAuthCallback(OAuthPendingState),
    /// Logged in with valid tokens
    LoggedIn(AuthSession),
    /// Error state
    Error(String),
}

/// State for pending OAuth authentication
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OAuthPendingState {
    /// Random state parameter for CSRF protection
    pub state: String,
    /// When the OAuth flow was started
    pub started_at: chrono::DateTime<chrono::Utc>,
}

impl Default for AuthState {
    fn default() -> Self {
        AuthState::LoggedOut
    }
}

/// Authenticated session with tokens
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthSession {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub user: UserInfo,
}

impl AuthSession {
    /// Check if the access token has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Check if the token will expire soon (within 5 minutes)
    pub fn expires_soon(&self) -> bool {
        Utc::now() + chrono::Duration::minutes(5) >= self.expires_at
    }
}

/// User information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
}

/// Supabase auth response
#[derive(Debug, Deserialize)]
pub struct SupabaseAuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub expires_at: Option<i64>,
    pub token_type: String,
    pub user: SupabaseUser,
}

/// Supabase user from auth response
#[derive(Debug, Deserialize)]
pub struct SupabaseUser {
    pub id: String,
    pub email: Option<String>,
}

/// VPN configuration from API
///
/// Field names use serde rename to match the API's camelCase response format.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnConfig {
    pub region: String,
    /// Server endpoint (IP:port), API returns as "serverEndpoint"
    #[serde(rename = "serverEndpoint")]
    pub endpoint: String,
    /// Server's WireGuard public key
    pub server_public_key: String,
    /// Client's private key (generated server-side)
    pub private_key: String,
    /// Client's public key
    pub public_key: String,
    /// Assigned IP for the client (e.g., "10.0.42.15/32")
    pub assigned_ip: String,
    /// Allowed IPs to route through VPN (e.g., ["0.0.0.0/0"])
    pub allowed_ips: Vec<String>,
    /// DNS servers to use
    pub dns: Vec<String>,
    /// Whether Phantun (TCP stealth) is available for this server
    #[serde(default)]
    pub phantun_enabled: bool,
    /// Phantun port (typically 443)
    #[serde(default)]
    pub phantun_port: Option<u16>,
}

/// Response from the desktop OAuth exchange API
#[derive(Debug, Clone, Deserialize)]
pub struct ExchangeTokenResponse {
    /// Type of token (always "magiclink")
    #[serde(rename = "type")]
    pub token_type: String,
    /// Magic link token to verify with Supabase
    pub token: String,
    /// User's email address
    pub email: String,
    /// User's ID
    pub user_id: String,
}

/// Error types for authentication
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Not authenticated")]
    NotAuthenticated,

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("API error: {0}")]
    ApiError(String),
}
