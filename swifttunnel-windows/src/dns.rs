//! Custom DNS resolver using Cloudflare DNS (1.1.1.1)
//!
//! Bypasses system DNS to avoid issues where ISP/network DNS blocks
//! domains like GitHub that the app needs to reach.

use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

/// Custom DNS resolver that queries Cloudflare DNS (1.1.1.1 / 1.0.0.1)
/// instead of the system resolver.
pub struct CloudflareDns {
    resolver: TokioAsyncResolver,
}

impl CloudflareDns {
    fn new() -> Self {
        let mut config = ResolverConfig::new();

        // Primary: 1.1.1.1 (UDP, TCP fallback)
        config.add_name_server(NameServerConfig::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
            Protocol::Udp,
        ));
        config.add_name_server(NameServerConfig::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
            Protocol::Tcp,
        ));

        // Fallback: 1.0.0.1 (UDP, TCP fallback)
        config.add_name_server(NameServerConfig::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 53),
            Protocol::Udp,
        ));
        config.add_name_server(NameServerConfig::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 53),
            Protocol::Tcp,
        ));

        let resolver = TokioAsyncResolver::tokio(config, ResolverOpts::default());

        Self { resolver }
    }

    /// Get a shared instance for use with reqwest `.dns_resolver()`
    pub fn shared() -> Arc<Self> {
        static INSTANCE: std::sync::OnceLock<Arc<CloudflareDns>> = std::sync::OnceLock::new();
        INSTANCE.get_or_init(|| Arc::new(Self::new())).clone()
    }

    /// Resolve a hostname to socket addresses (for non-reqwest usage like VPN relay)
    pub async fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
        let lookup = self
            .resolver
            .lookup_ip(host)
            .await
            .map_err(|e| format!("DNS resolution failed for '{}': {}", host, e))?;

        let addrs: Vec<SocketAddr> = lookup.into_iter().map(|ip| SocketAddr::new(ip, port)).collect();

        if addrs.is_empty() {
            return Err(format!("DNS resolution returned no addresses for '{}'", host));
        }

        Ok(addrs)
    }
}

impl reqwest::dns::Resolve for CloudflareDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let resolver = self.resolver.clone();
        Box::pin(async move {
            let lookup = resolver
                .lookup_ip(name.as_str())
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

            let addrs: reqwest::dns::Addrs =
                Box::new(lookup.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}
