//! Roblox network bypass proxy.
//!
//! A local-only TCP relay that routes Roblox HTTPS traffic through
//! loopback to bypass restrictive WiFi networks. Works by:
//!
//! 1. Redirecting Roblox domains to `127.66.0.1` via the hosts file.
//! 2. Resolving the real IP via DNS-over-HTTPS (bypasses DNS filtering).
//! 3. Optionally fragmenting the TLS ClientHello so the SNI spans
//!    multiple TCP segments (bypasses SNI-based DPI).
//!
//! No TLS termination — the relay operates at TCP level only.

pub mod doh;
pub mod hosts;
pub mod relay;
pub mod sni_parser;

pub use relay::{ProxyState, ProxyStatsSnapshot, RobloxProxy};

#[derive(Debug, thiserror::Error)]
pub enum RobloxProxyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Hosts file error: {0}")]
    HostsFile(String),

    #[error("Proxy already running")]
    AlreadyRunning,
}
