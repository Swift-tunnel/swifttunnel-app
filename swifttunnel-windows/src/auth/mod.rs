//! Authentication module for SwiftTunnel Desktop
//!
//! Handles authentication via Supabase:
//! - Direct email/password sign-in
//! - Google OAuth via localhost callback server
//! - Secure token storage via Keychain
//! - Token refresh management

mod http_client;
mod manager;
pub mod oauth_server;
mod storage;
pub mod types;

pub use manager::AuthManager;
pub use oauth_server::{OAuthServer, OAuthCallbackData, OAuthServerResult, DEFAULT_OAUTH_PORT};
pub use types::*;
