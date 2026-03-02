//! TCP relay engine for the Roblox network bypass proxy.
//!
//! Listens on `127.66.0.1:443` (HTTPS) and `127.66.0.1:80` (HTTP),
//! resolves the target hostname via DoH, optionally fragments the
//! TLS ClientHello, and relays traffic bidirectionally.
//!
//! No TLS termination — the relay operates at TCP level only.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::RobloxProxyError;
use super::doh::DohResolver;
use super::hosts;
use super::sni_parser;

const BIND_ADDR: &str = "127.66.0.1";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyState {
    Stopped,
    Starting,
    Running,
    Error(String),
}

/// Snapshot of proxy statistics (all counters are monotonic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStatsSnapshot {
    pub active_connections: u64,
    pub total_connections: u64,
    pub bytes_relayed: u64,
}

// ---------------------------------------------------------------------------
// Internal shared stats (atomic, lock-free)
// ---------------------------------------------------------------------------

pub(crate) struct ProxyStats {
    active: AtomicU64,
    total: AtomicU64,
    bytes: AtomicU64,
}

impl ProxyStats {
    fn new() -> Self {
        Self {
            active: AtomicU64::new(0),
            total: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> ProxyStatsSnapshot {
        ProxyStatsSnapshot {
            active_connections: self.active.load(Ordering::Relaxed),
            total_connections: self.total.load(Ordering::Relaxed),
            bytes_relayed: self.bytes.load(Ordering::Relaxed),
        }
    }

    fn reset(&self) {
        self.active.store(0, Ordering::Relaxed);
        self.total.store(0, Ordering::Relaxed);
        self.bytes.store(0, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// RobloxProxy
// ---------------------------------------------------------------------------

pub struct RobloxProxy {
    state: ProxyState,
    sni_fragment: bool,
    resolver: Arc<DohResolver>,
    shutdown_tx: Option<watch::Sender<bool>>,
    stats: Arc<ProxyStats>,
    tasks: Vec<JoinHandle<()>>,
}

impl RobloxProxy {
    pub fn new() -> Self {
        Self {
            state: ProxyState::Stopped,
            sni_fragment: false,
            resolver: Arc::new(DohResolver::new()),
            shutdown_tx: None,
            stats: Arc::new(ProxyStats::new()),
            tasks: Vec::new(),
        }
    }

    pub fn state(&self) -> &ProxyState {
        &self.state
    }

    pub fn stats(&self) -> ProxyStatsSnapshot {
        self.stats.snapshot()
    }

    /// Start the proxy: bind listeners first, then apply hosts overrides.
    ///
    /// Binding before modifying the hosts file eliminates a race condition
    /// where DNS resolves to `127.66.0.1` before anything is accepting
    /// connections, causing Roblox to time out on `clientsettingscdn.roblox.com`.
    pub async fn start(&mut self, sni_fragment: bool) -> Result<(), RobloxProxyError> {
        if self.state == ProxyState::Running {
            return Err(RobloxProxyError::AlreadyRunning);
        }

        self.state = ProxyState::Starting;
        self.sni_fragment = sni_fragment;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);
        self.stats.reset();

        // Bind listeners BEFORE modifying the hosts file so that connections
        // are accepted the instant DNS starts resolving to our address.
        let listener_443 = match TcpListener::bind(format!("{BIND_ADDR}:443")).await {
            Ok(l) => l,
            Err(e) => {
                self.state = ProxyState::Error(e.to_string());
                return Err(RobloxProxyError::Io(e));
            }
        };

        let listener_80 = match TcpListener::bind(format!("{BIND_ADDR}:80")).await {
            Ok(l) => l,
            Err(e) => {
                self.state = ProxyState::Error(e.to_string());
                return Err(RobloxProxyError::Io(e));
            }
        };

        info!("Roblox proxy listening on {BIND_ADDR}:443 and {BIND_ADDR}:80");

        // Spawn HTTPS accept loop
        {
            let resolver = self.resolver.clone();
            let stats = self.stats.clone();
            let sni_frag = self.sni_fragment;
            let mut rx = shutdown_rx.clone();

            self.tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = rx.changed() => {
                            info!("HTTPS proxy listener shutting down");
                            break;
                        }
                        result = listener_443.accept() => {
                            match result {
                                Ok((stream, _addr)) => {
                                    let r = resolver.clone();
                                    let s = stats.clone();
                                    tokio::spawn(handle_tls_connection(stream, r, s, sni_frag));
                                }
                                Err(e) => warn!("HTTPS accept error: {e}"),
                            }
                        }
                    }
                }
            }));
        }

        // Spawn HTTP accept loop
        {
            let resolver = self.resolver.clone();
            let stats = self.stats.clone();
            let mut rx = shutdown_rx;

            self.tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = rx.changed() => {
                            info!("HTTP proxy listener shutting down");
                            break;
                        }
                        result = listener_80.accept() => {
                            match result {
                                Ok((stream, _addr)) => {
                                    let r = resolver.clone();
                                    let s = stats.clone();
                                    tokio::spawn(handle_http_connection(stream, r, s));
                                }
                                Err(e) => warn!("HTTP accept error: {e}"),
                            }
                        }
                    }
                }
            }));
        }

        // NOW apply hosts file redirects — listeners are already accepting
        // connections, so any DNS resolution hitting 127.66.0.1 will succeed.
        if let Err(e) = hosts::apply_overrides() {
            // Listeners are up but hosts failed — tear down everything.
            if let Some(tx) = self.shutdown_tx.take() {
                let _ = tx.send(true);
            }
            for task in self.tasks.drain(..) {
                task.abort();
            }
            self.state = ProxyState::Error(e.clone());
            return Err(RobloxProxyError::HostsFile(e));
        }

        self.state = ProxyState::Running;
        info!("Roblox proxy started (SNI fragmentation: {})", sni_fragment);
        Ok(())
    }

    /// Stop the proxy: tear down listeners and remove hosts overrides.
    pub async fn stop(&mut self) -> Result<(), RobloxProxyError> {
        if self.state == ProxyState::Stopped {
            return Ok(());
        }

        info!("Stopping Roblox proxy...");

        // Signal shutdown
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }

        // Abort listener tasks
        for task in self.tasks.drain(..) {
            task.abort();
        }

        // Remove hosts entries
        if let Err(e) = hosts::remove_overrides() {
            warn!("Failed to remove hosts overrides during shutdown: {e}");
        }

        self.state = ProxyState::Stopped;
        info!("Roblox proxy stopped");
        Ok(())
    }
}

impl Drop for RobloxProxy {
    fn drop(&mut self) {
        if self.state == ProxyState::Running || self.state == ProxyState::Starting {
            for task in self.tasks.drain(..) {
                task.abort();
            }
            if let Err(e) = hosts::remove_overrides() {
                warn!("Failed to clean up hosts file on drop: {e}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-connection handlers
// ---------------------------------------------------------------------------

async fn handle_tls_connection(
    mut client: TcpStream,
    resolver: Arc<DohResolver>,
    stats: Arc<ProxyStats>,
    sni_fragment: bool,
) {
    stats.active.fetch_add(1, Ordering::Relaxed);
    stats.total.fetch_add(1, Ordering::Relaxed);

    if let Err(e) = relay_tls(&mut client, &resolver, &stats, sni_fragment).await {
        debug!("TLS relay finished: {e}");
    }

    stats.active.fetch_sub(1, Ordering::Relaxed);
}

async fn relay_tls(
    client: &mut TcpStream,
    resolver: &DohResolver,
    stats: &ProxyStats,
    sni_fragment: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read the initial data (contains the ClientHello)
    let mut buf = vec![0u8; 16384]; // max TLS record size
    let n = client.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let initial = &buf[..n];

    // Extract SNI hostname
    let sni = sni_parser::parse_sni(initial).ok_or("no SNI in ClientHello")?;
    debug!("TLS relay: SNI={}", sni.hostname);

    // Resolve via DoH
    let addrs = resolver.resolve(&sni.hostname).await?;
    let addr = *addrs.first().ok_or("no addresses resolved")?;

    // Connect upstream
    let mut upstream = TcpStream::connect((addr, 443u16)).await?;

    // Forward ClientHello (with optional fragmentation)
    if sni_fragment && sni.hostname_offset + sni.hostname_len <= n {
        let split = sni.hostname_offset + sni.hostname_len / 2;
        upstream.set_nodelay(true)?;
        upstream.write_all(&initial[..split]).await?;
        upstream.flush().await?;
        upstream.write_all(&initial[split..]).await?;
        upstream.flush().await?;
    } else {
        upstream.write_all(initial).await?;
    }

    // Bidirectional relay
    let (tx, rx) = tokio::io::copy_bidirectional(client, &mut upstream).await?;
    stats
        .bytes
        .fetch_add(tx + rx + initial.len() as u64, Ordering::Relaxed);

    Ok(())
}

async fn handle_http_connection(
    mut client: TcpStream,
    resolver: Arc<DohResolver>,
    stats: Arc<ProxyStats>,
) {
    stats.active.fetch_add(1, Ordering::Relaxed);
    stats.total.fetch_add(1, Ordering::Relaxed);

    if let Err(e) = relay_http(&mut client, &resolver, &stats).await {
        debug!("HTTP relay finished: {e}");
    }

    stats.active.fetch_sub(1, Ordering::Relaxed);
}

async fn relay_http(
    client: &mut TcpStream,
    resolver: &DohResolver,
    stats: &ProxyStats,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = vec![0u8; 8192];
    let n = client.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let initial = &buf[..n];

    let host = sni_parser::parse_http_host(initial).ok_or("no Host header")?;
    debug!("HTTP relay: Host={host}");

    let addrs = resolver.resolve(&host).await?;
    let addr = *addrs.first().ok_or("no addresses resolved")?;

    let mut upstream = TcpStream::connect((addr, 80u16)).await?;
    upstream.write_all(initial).await?;

    let (tx, rx) = tokio::io::copy_bidirectional(client, &mut upstream).await?;
    stats
        .bytes
        .fetch_add(tx + rx + initial.len() as u64, Ordering::Relaxed);

    Ok(())
}
