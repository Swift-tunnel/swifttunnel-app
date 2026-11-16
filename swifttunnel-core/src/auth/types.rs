//! Authentication types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// Debug must never become an accidental credential export. Serialization is
// unchanged: authentication and encrypted storage still need the real values.
macro_rules! redacted_debug {
    ($kind:ident, [$($public:ident),*], [$($secret:ident),*]) => {
        impl std::fmt::Debug for $kind {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let mut record = f.debug_struct(stringify!($kind));
                $(record.field(stringify!($public), &self.$public);)*
                $(let _ = &self.$secret; record.field(stringify!($secret), &"[redacted]");)*
                record.finish()
            }
        }
    };
}

/// Authentication state
#[derive(Debug, Clone, PartialEq, Default)]
pub enum AuthState {
    /// Not logged in
    #[default]
    LoggedOut,
    /// Login in progress (email/password)
    LoggingIn,
    /// Waiting for OAuth callback from browser
    AwaitingOAuthCallback(OAuthPendingState),
    /// Logged in with valid tokens
    LoggedIn(AuthSession),
    /// Account is banned. Retained tokens allow status rechecks and sign-out,
    /// while ordinary authenticated access remains blocked.
    Banned(AuthSession),
    /// Error state
    Error(String),
}

/// State for pending OAuth authentication
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct OAuthPendingState {
    /// Random state parameter for CSRF protection
    pub state: String,
    /// When the OAuth flow was started
    pub started_at: chrono::DateTime<chrono::Utc>,
}
redacted_debug!(OAuthPendingState, [started_at], [state]);

/// Authenticated session with tokens
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthSession {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub user: UserInfo,
}
redacted_debug!(
    AuthSession,
    [expires_at, user],
    [access_token, refresh_token]
);

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
    /// Whether admin has blocked this account from desktop access.
    #[serde(default)]
    pub is_banned: bool,
    #[serde(default)]
    pub banned_reason: Option<String>,
    #[serde(default)]
    pub banned_at: Option<String>,
}

/// Supabase auth response
#[derive(Deserialize)]
pub struct SupabaseAuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(deserialize_with = "deserialize_expires_in")]
    pub expires_in: i64,
    pub expires_at: Option<i64>,
    pub token_type: String,
    pub user: SupabaseUser,
}
redacted_debug!(
    SupabaseAuthResponse,
    [expires_in, expires_at, token_type, user],
    [access_token, refresh_token]
);

// Supabase's documented maximum JWT lifetime is seven days. Invalid API
// numbers must not reach Duration::seconds or DateTime addition, both of
// which can panic on an overflowing lifetime.
// https://supabase.com/docs/guides/self-hosting/auth/config
const MAX_ACCESS_TOKEN_LIFETIME_SECONDS: i64 = 7 * 24 * 60 * 60;

fn validate_expires_in(value: i64) -> Result<i64, &'static str> {
    if (1..=MAX_ACCESS_TOKEN_LIFETIME_SECONDS).contains(&value) {
        Ok(value)
    } else {
        Err("invalid access-token lifetime")
    }
}

fn deserialize_expires_in<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<i64, D::Error> {
    validate_expires_in(i64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
}

fn deserialize_optional_expires_in<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<i64>, D::Error> {
    Option::<i64>::deserialize(deserializer)?
        .map(validate_expires_in)
        .transpose()
        .map_err(serde::de::Error::custom)
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
#[derive(Clone, Default, Serialize, Deserialize)]
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
redacted_debug!(
    VpnConfig,
    [
        id,
        region,
        endpoint,
        server_public_key,
        public_key,
        assigned_ip,
        allowed_ips,
        dns,
        phantun_enabled,
        phantun_port
    ],
    [private_key]
);

/// Response from the desktop OAuth exchange API
#[derive(Clone, Deserialize)]
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
    /// Ready session returned by the SwiftTunnel web fallback.
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_expires_in")]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default, rename = "token_type")]
    pub session_token_type: Option<String>,
}
redacted_debug!(
    ExchangeTokenResponse,
    [
        token_type,
        email,
        user_id,
        expires_in,
        expires_at,
        session_token_type
    ],
    [token, access_token, refresh_token]
);

/// Relay connection policy delivered by relay ticket bootstrap endpoint.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum RelayPreflightMode {
    #[default]
    Legacy,
    Enforce,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum RelayQueueFullMode {
    #[default]
    Bypass,
    Drop,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct RelayConnectionPolicy {
    #[serde(default)]
    pub preflight_mode: RelayPreflightMode,
    #[serde(default)]
    pub queue_full_mode: RelayQueueFullMode,
}

/// Response from relay ticket bootstrap endpoint
#[derive(Clone, Deserialize)]
pub struct RelayTicketResponse {
    pub token: String,
    pub expires_at: String,
    pub auth_required: bool,
    pub key_id: String,
    #[serde(default)]
    pub connection_policy: Option<RelayConnectionPolicy>,
    /// Free-tier time budget in seconds, refreshed on every ticket (~2 min).
    /// `None` means no limit applies — either the backend has it switched off,
    /// or it predates the feature and omits the fields entirely.
    #[serde(default)]
    pub limit_seconds: Option<i64>,
    #[serde(default)]
    pub remaining_seconds: Option<i64>,
    /// When the allowance refills, as the server sees it.
    ///
    /// The budget above is only refreshed while a ticket is being fetched, so
    /// a client sitting disconnected keeps reporting whatever it last heard.
    /// Overnight that is yesterday's exhausted figure, and Lite refuses to
    /// even attempt a connection when the allowance reads as spent, so the
    /// button went dead until the app was restarted.
    ///
    /// Knowing when the server will refill removes the guesswork: past this
    /// instant the recorded budget is simply out of date and the full
    /// allowance is assumed until the next ticket says otherwise.
    #[serde(default)]
    pub resets_at: Option<DateTime<Utc>>,
    /// Seconds of grace left after the allowance ran out, or `None` when not in
    /// grace. The backend keeps issuing leases through this window, so the
    /// session is still live and the client must NOT hang up — it warns and
    /// counts down instead. Hanging up at `remaining_seconds == 0` would throw
    /// the user out of a match the server was deliberately letting them finish.
    #[serde(default)]
    pub grace_seconds: Option<i64>,
    /// The relay this ticket is for is past its comfortable occupancy. The
    /// ticket is still valid — a busy relay beats a refused connection — but the
    /// user is better off elsewhere.
    ///
    /// Only reachable when someone has pinned a specific server; automatic
    /// selection already steers around load.
    #[serde(default)]
    pub degraded: bool,
    /// A quieter relay in the same city, when one exists. `None` means nothing
    /// is meaningfully better, so say nothing rather than nag.
    #[serde(default)]
    pub suggested_region: Option<String>,
}
redacted_debug!(
    RelayTicketResponse,
    [
        expires_at,
        auth_required,
        key_id,
        connection_policy,
        limit_seconds,
        remaining_seconds,
        resets_at,
        grace_seconds,
        degraded,
        suggested_region
    ],
    [token]
);

impl RelayTicketResponse {
    pub fn preflight_mode(&self) -> RelayPreflightMode {
        self.connection_policy
            .as_ref()
            .map(|policy| policy.preflight_mode)
            .unwrap_or_default()
    }

    pub fn queue_full_mode(&self) -> RelayQueueFullMode {
        self.connection_policy
            .as_ref()
            .map(|policy| policy.queue_full_mode)
            .unwrap_or_default()
    }
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

    #[error("Invalid email or password")]
    InvalidCredentials,

    #[error("Session expired, please sign in again")]
    RefreshTokenInvalid,

    #[error("Account banned{0}")]
    UserBanned(String),

    /// The server rejected this build as too old (old-build lockout). The string
    /// is the user-facing "please update" message from the API.
    #[error("{0}")]
    UpdateRequired(String),

    /// The account has spent its free-tier allowance. The string is the
    /// user-facing message from the API, which owns the wording (it names the
    /// current hour limit and says the cap is temporary).
    #[error("{0}")]
    FreeTierLimitReached(String),

    /// The API answered 429, or ticket issuance is busy (503). Unlike `ApiError`, it must never be
    /// retried straight away: being throttled says nothing about whether
    /// the session is still valid.
    ///
    /// Carries the server's `Retry-After` in seconds.
    #[error("Rate limited by the API; retry in {0}s")]
    RateLimited(u64),
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn sensitive_debug_output_redacts_credentials_but_not_session_serialization() {
        let session: AuthSession = serde_json::from_value(serde_json::json!({
            "access_token": "fixture-private-access", "refresh_token": "fixture-private-refresh",
            "expires_at": "2026-10-29T00:00:00Z", "user": { "id": "fixture-user", "email": "fixture@example.invalid" }
        })).unwrap();
        let stored = serde_json::to_value(&session).unwrap();
        assert_eq!(stored["access_token"], "fixture-private-access");
        assert_eq!(stored["refresh_token"], "fixture-private-refresh");
        let auth: SupabaseAuthResponse = serde_json::from_value(serde_json::json!({
            "access_token": "fixture-private-access", "refresh_token": "fixture-private-refresh",
            "expires_in": 3600, "token_type": "bearer", "user": {"id":"fixture-user"}
        }))
        .unwrap();
        let exchange: ExchangeTokenResponse = serde_json::from_value(serde_json::json!({
            "type": "magiclink", "token": "fixture-private-magic", "email":"fixture@example.invalid", "user_id":"fixture-user",
            "access_token": "fixture-private-access", "refresh_token": "fixture-private-refresh"
        })).unwrap();
        let ticket: RelayTicketResponse = serde_json::from_value(serde_json::json!({
            "token":"fixture-private-ticket", "expires_at":"later", "auth_required":true, "key_id":"public-key-id"
        })).unwrap();
        let config = VpnConfig {
            private_key: "fixture-private-vpn".into(),
            ..Default::default()
        };
        let pending = AuthState::AwaitingOAuthCallback(OAuthPendingState {
            state: "fixture-private-state".into(),
            started_at: Utc::now(),
        });
        for output in [
            format!("{:?}", AuthState::LoggedIn(session.clone())),
            format!("{:?}", AuthState::Banned(session)),
            format!("{auth:?}"),
            format!("{exchange:?}"),
            format!("{ticket:?}"),
            format!("{config:?}"),
            format!("{pending:?}"),
        ] {
            assert!(
                !output.contains("fixture-private-"),
                "credential exposed in debug: {output}"
            );
            assert!(output.contains("[redacted]"));
        }
    }

    #[test]
    fn malformed_access_token_lifetimes_are_rejected_before_session_arithmetic() {
        let mut auth = serde_json::json!({
            "access_token":"test-access", "refresh_token":"test-refresh",
            "expires_in":3600, "token_type":"bearer", "user":{"id":"test-user"},
        });
        let mut exchange = serde_json::json!({
            "type":"magiclink", "token":"test-code", "email":"owned@example.invalid",
            "user_id":"test-user", "expires_in":3600,
        });
        for lifetime in [
            i64::MIN,
            -1,
            0,
            MAX_ACCESS_TOKEN_LIFETIME_SECONDS + 1,
            i64::MAX,
        ] {
            auth["expires_in"] = lifetime.into();
            exchange["expires_in"] = lifetime.into();
            assert!(serde_json::from_value::<SupabaseAuthResponse>(auth.clone()).is_err());
            assert!(serde_json::from_value::<ExchangeTokenResponse>(exchange.clone()).is_err());
        }
        for lifetime in [1, 3600, MAX_ACCESS_TOKEN_LIFETIME_SECONDS] {
            auth["expires_in"] = lifetime.into();
            exchange["expires_in"] = lifetime.into();
            assert_eq!(
                serde_json::from_value::<SupabaseAuthResponse>(auth.clone())
                    .unwrap()
                    .expires_in,
                lifetime
            );
            assert_eq!(
                serde_json::from_value::<ExchangeTokenResponse>(exchange.clone())
                    .unwrap()
                    .expires_in,
                Some(lifetime)
            );
        }
        exchange.as_object_mut().unwrap().remove("expires_in");
        assert!(
            serde_json::from_value::<ExchangeTokenResponse>(exchange.clone())
                .unwrap()
                .expires_in
                .is_none()
        );
        exchange["expires_in"] = serde_json::Value::Null;
        assert!(
            serde_json::from_value::<ExchangeTokenResponse>(exchange)
                .unwrap()
                .expires_in
                .is_none()
        );
    }

    fn make_session(expires_at: DateTime<Utc>) -> AuthSession {
        AuthSession {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at,
            user: UserInfo {
                id: "user-1".to_string(),
                email: "test@example.com".to_string(),
                is_tester: false,
                is_banned: false,
                banned_reason: None,
                banned_at: None,
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
        assert_eq!(
            AuthError::UserBanned(": abuse".to_string()).to_string(),
            "Account banned: abuse"
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
    fn test_relay_ticket_response_deserialize_without_policy() {
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
        assert_eq!(resp.preflight_mode(), RelayPreflightMode::Legacy);
        assert_eq!(resp.queue_full_mode(), RelayQueueFullMode::Bypass);
    }

    #[test]
    fn test_relay_ticket_response_deserialize_with_policy() {
        let json = r#"{
            "token": "abc.def",
            "expires_at": "2026-02-17T12:34:56.000Z",
            "auth_required": true,
            "key_id": "relay-ed25519-2026-02",
            "connection_policy": {
                "preflight_mode": "enforce",
                "queue_full_mode": "drop"
            }
        }"#;
        let resp: RelayTicketResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.preflight_mode(), RelayPreflightMode::Enforce);
        assert_eq!(resp.queue_full_mode(), RelayQueueFullMode::Drop);
    }
}
