//! Authentication module for SwiftTunnel Desktop
//!
//! Handles authentication via Supabase:
//! - Direct email/password sign-in
//! - Secure token storage via Keychain
//! - Token refresh management

mod http_client;
mod manager;
mod storage;
pub mod types;

pub use manager::AuthManager;
pub use types::*;
