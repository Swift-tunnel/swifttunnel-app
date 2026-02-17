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
    /// Whether user has tester access (gates experimental features)
    #[serde(default)]
    pub is_tester: bool,
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
    /// Config ID (UUID from database)
    #[serde(default)]
    pub id: String,
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

/// Response from relay ticket bootstrap endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct RelayTicketResponse {
    pub token: String,
    pub expires_at: String,
    pub auth_required: bool,
    pub key_id: String,
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

    #[error("Session expired, please sign in again")]
    RefreshTokenInvalid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn make_session(expires_at: DateTime<Utc>) -> AuthSession {
        AuthSession {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at,
            user: UserInfo {
                id: "user-1".to_string(),
                email: "test@example.com".to_string(),
                is_tester: false,
            },
        }
    }

    #[test]
    fn test_auth_session_is_expired_when_past() {
        let session = make_session(Utc::now() - Duration::hours(1));
        assert!(session.is_expired());
    }

    #[test]
    fn test_auth_session_is_not_expired_when_future() {
        let session = make_session(Utc::now() + Duration::hours(1));
        assert!(!session.is_expired());
    }

    #[test]
    fn test_auth_session_expires_soon_when_less_than_5_min() {
        let session = make_session(Utc::now() + Duration::minutes(3));
        assert!(session.expires_soon());
    }

    #[test]
    fn test_auth_session_not_expires_soon_when_more_than_5_min() {
        let session = make_session(Utc::now() + Duration::minutes(10));
        assert!(!session.expires_soon());
    }

    #[test]
    fn test_auth_state_default_is_logged_out() {
        assert_eq!(AuthState::default(), AuthState::LoggedOut);
    }

    #[test]
    fn test_vpn_config_deserialize_camel_case() {
        let json = r#"{
            "id": "cfg-123",
            "region": "us-east",
            "serverEndpoint": "1.2.3.4:51820",
            "serverPublicKey": "pubkey123",
            "privateKey": "privkey456",
            "publicKey": "clientpub789",
            "assignedIp": "10.0.42.15/32",
            "allowedIps": ["0.0.0.0/0"],
            "dns": ["1.1.1.1"],
            "phantunEnabled": false,
            "phantunPort": null
        }"#;
        let config: VpnConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.region, "us-east");
        assert_eq!(config.endpoint, "1.2.3.4:51820");
        assert_eq!(config.server_public_key, "pubkey123");
        assert_eq!(config.private_key, "privkey456");
        assert_eq!(config.public_key, "clientpub789");
        assert_eq!(config.assigned_ip, "10.0.42.15/32");
        assert_eq!(config.allowed_ips, vec!["0.0.0.0/0"]);
        assert_eq!(config.dns, vec!["1.1.1.1"]);
        assert!(!config.phantun_enabled);
        assert!(config.phantun_port.is_none());
    }

    #[test]
    fn test_exchange_token_response_deserialize() {
        let json = r#"{
            "type": "magiclink",
            "token": "tok-abc",
            "email": "user@example.com",
            "user_id": "uid-123"
        }"#;
        let resp: ExchangeTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.token_type, "magiclink");
        assert_eq!(resp.token, "tok-abc");
        assert_eq!(resp.email, "user@example.com");
        assert_eq!(resp.user_id, "uid-123");
    }

    #[test]
    fn test_auth_error_display() {
        assert_eq!(AuthError::NotAuthenticated.to_string(), "Not authenticated");
        assert_eq!(
            AuthError::NetworkError("timeout".to_string()).to_string(),
            "Network error: timeout"
        );
        assert_eq!(
            AuthError::StorageError("disk full".to_string()).to_string(),
            "Storage error: disk full"
        );
        assert_eq!(
            AuthError::ApiError("401".to_string()).to_string(),
            "API error: 401"
        );
        assert_eq!(
            AuthError::RefreshTokenInvalid.to_string(),
            "Session expired, please sign in again"
        );
    }

    #[test]
    fn test_refresh_token_invalid_is_matchable() {
        // Ensures the retry-skip logic in manager.rs can pattern-match this variant
        let err = AuthError::RefreshTokenInvalid;
        assert!(matches!(err, AuthError::RefreshTokenInvalid));
        // Transient errors must NOT match
        let transient = AuthError::NetworkError("timeout".to_string());
        assert!(!matches!(transient, AuthError::RefreshTokenInvalid));
        let api_err = AuthError::ApiError("500 internal".to_string());
        assert!(!matches!(api_err, AuthError::RefreshTokenInvalid));
    }

    #[test]
    fn test_relay_ticket_response_deserialize() {
        let json = r#"{
            "token": "abc.def",
            "expires_at": "2026-02-17T12:34:56.000Z",
            "auth_required": false,
            "key_id": "relay-ed25519-2026-02"
        }"#;
        let resp: RelayTicketResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.token, "abc.def");
        assert_eq!(resp.expires_at, "2026-02-17T12:34:56.000Z");
        assert!(!resp.auth_required);
        assert_eq!(resp.key_id, "relay-ed25519-2026-02");
    }
}
