//! WireGuard Tunnel Implementation using BoringTun
//!
//! This module implements the WireGuard protocol using BoringTun (Cloudflare's
//! userspace WireGuard implementation). It handles:
//! - Noise protocol handshake
//! - Packet encryption/decryption
//! - Keepalive management
//! - Bidirectional packet routing

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use boringtun::noise::{Tunn, TunnResult};
use super::adapter::WintunAdapter;
use super::config::parse_key;
use super::{VpnError, VpnResult};
use crate::auth::types::VpnConfig;

/// WireGuard keepalive interval in seconds (sent to peer)
const KEEPALIVE_INTERVAL: u16 = 25;

/// BoringTun tick interval in milliseconds (for internal timer management)
/// Must be called frequently to handle handshakes, keepalives, and timeouts
const TICK_INTERVAL_MS: u64 = 100;

/// Maximum packet size
const MAX_PACKET_SIZE: usize = 65535;

/// Tunnel statistics
#[derive(Debug, Clone, Default)]
pub struct TunnelStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub handshakes: u64,
    pub last_handshake_time: Option<std::time::Instant>,
}

/// Type for inbound packet handler callback
/// Called with decrypted IP packets that should be injected to split tunnel apps
pub type InboundHandler = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// WireGuard tunnel wrapper
pub struct WireguardTunnel {
    config: VpnConfig,
    endpoint: SocketAddr,
    running: Arc<AtomicBool>,
    stats: Arc<std::sync::Mutex<TunnelStats>>,
    /// Optional handler for inbound packets when split tunnel is active
    /// If set, decrypted packets are passed to this handler instead of Wintun
    inbound_handler: Arc<std::sync::Mutex<Option<InboundHandler>>>,
}

impl WireguardTunnel {
    /// Create a new WireGuard tunnel
    pub fn new(config: VpnConfig) -> VpnResult<Self> {
        let endpoint = super::config::parse_endpoint(&config.endpoint)?;

        log::info!("Creating WireGuard tunnel to {}", endpoint);

        Ok(Self {
            config,
            endpoint,
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(std::sync::Mutex::new(TunnelStats::default())),
            inbound_handler: Arc::new(std::sync::Mutex::new(None)),
        })
    }

    /// Set the inbound packet handler for split tunnel mode
    ///
    /// When set, decrypted inbound packets are passed to this handler
    /// instead of being written to the Wintun adapter. The handler should
    /// inject the packets to the appropriate network interface.
    pub fn set_inbound_handler(&self, handler: InboundHandler) {
        log::info!("Setting inbound packet handler for split tunnel");
        *self.inbound_handler.lock().unwrap() = Some(handler);
    }

    /// Get the inbound handler (for passing to tasks)
    fn get_inbound_handler(&self) -> Arc<std::sync::Mutex<Option<InboundHandler>>> {
        Arc::clone(&self.inbound_handler)
    }

    /// Start the tunnel packet processing loops
    ///
    /// This spawns two async tasks:
    /// 1. Outbound: Wintun adapter -> encrypt -> UDP to server
    /// 2. Inbound: UDP from server -> decrypt -> Wintun adapter
    pub async fn start(&self, adapter: Arc<WintunAdapter>) -> VpnResult<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(VpnError::TunnelInit("Tunnel already running".to_string()));
        }

        log::info!("Starting WireGuard tunnel");

        // Parse keys
        let private_key = parse_key(&self.config.private_key)?;
        let peer_public_key = parse_key(&self.config.server_public_key)?;

        // Create BoringTun instance
        let tunn = Tunn::new(
            private_key.into(),
            peer_public_key.into(),
            None, // No preshared key
            Some(KEEPALIVE_INTERVAL),
            0, // Tunnel index
            None, // No rate limiter
        ).map_err(|e| VpnError::TunnelInit(format!("Failed to create Tunn: {:?}", e)))?;

        let tunn = Arc::new(std::sync::Mutex::new(tunn));

        // Create UDP socket for server communication
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| VpnError::Network(format!("Failed to bind UDP socket: {}", e)))?;

        socket
            .connect(self.endpoint)
            .await
            .map_err(|e| VpnError::Network(format!("Failed to connect to endpoint: {}", e)))?;

        let socket = Arc::new(socket);

        self.running.store(true, Ordering::SeqCst);

        // Perform initial handshake
        self.initiate_handshake(&tunn, &socket).await?;

        // Create channel for shutdown coordination
        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

        // Spawn outbound task (adapter -> server)
        let outbound_handle = self.spawn_outbound_task(
            Arc::clone(&adapter),
            Arc::clone(&tunn),
            Arc::clone(&socket),
            Arc::clone(&self.running),
            Arc::clone(&self.stats),
            shutdown_tx.subscribe(),
        );

        // Spawn inbound task (server -> adapter)
        let inbound_handle = self.spawn_inbound_task(
            Arc::clone(&adapter),
            Arc::clone(&tunn),
            Arc::clone(&socket),
            Arc::clone(&self.running),
            Arc::clone(&self.stats),
            self.get_inbound_handler(),
            shutdown_tx.subscribe(),
        );

        // Spawn keepalive task
        let keepalive_handle = self.spawn_keepalive_task(
            Arc::clone(&tunn),
            Arc::clone(&socket),
            Arc::clone(&self.running),
            shutdown_tx.subscribe(),
        );

        log::info!("WireGuard tunnel started successfully");

        // Wait for all tasks (they will exit when running becomes false)
        tokio::select! {
            _ = outbound_handle => log::info!("Outbound task finished"),
            _ = inbound_handle => log::info!("Inbound task finished"),
            _ = keepalive_handle => log::info!("Keepalive task finished"),
        }

        Ok(())
    }

    /// Initiate the WireGuard handshake
    async fn initiate_handshake(
        &self,
        tunn: &Arc<std::sync::Mutex<Tunn>>,
        socket: &Arc<UdpSocket>,
    ) -> VpnResult<()> {
        log::info!("Initiating WireGuard handshake");

        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        // Get handshake initiation packet
        let handshake_init = {
            let mut tunn = tunn.lock().unwrap();
            tunn.format_handshake_initiation(&mut buf, false)
        };

        match handshake_init {
            TunnResult::WriteToNetwork(data) => {
                socket
                    .send(data)
                    .await
                    .map_err(|e| VpnError::Network(format!("Failed to send handshake: {}", e)))?;
                log::info!("Handshake initiation sent ({} bytes)", data.len());
            }
            _ => {
                return Err(VpnError::HandshakeFailed(
                    "Failed to generate handshake initiation".to_string(),
                ));
            }
        }

        // Wait for handshake response with timeout
        let mut response_buf = vec![0u8; MAX_PACKET_SIZE];
        let timeout = Duration::from_secs(10);

        let recv_result = tokio::time::timeout(timeout, socket.recv(&mut response_buf)).await;

        match recv_result {
            Ok(Ok(n)) => {
                let result = {
                    let mut tunn = tunn.lock().unwrap();
                    let decap_result = tunn.decapsulate(None, &response_buf[..n], &mut buf);
                    // Copy data if we need to send, since we can't hold the guard across await
                    match decap_result {
                        TunnResult::WriteToNetwork(data) => {
                            Some(data.to_vec())
                        }
                        other => {
                            // Return the result directly for non-network cases
                            return match other {
                                TunnResult::Done => {
                                    log::info!("WireGuard handshake completed successfully");
                                    Ok(())
                                }
                                TunnResult::Err(e) => {
                                    Err(VpnError::HandshakeFailed(format!("Handshake error: {:?}", e)))
                                }
                                _ => {
                                    log::warn!("Unexpected handshake result: continuing anyway");
                                    Ok(())
                                }
                            };
                        }
                    }
                };

                // Guard is dropped here, now we can await
                if let Some(data) = result {
                    socket.send(&data).await.ok();
                    log::info!("WireGuard handshake completed (with response)");
                }
                Ok(())
            }
            Ok(Err(e)) => Err(VpnError::HandshakeFailed(format!("Receive error: {}", e))),
            Err(_) => Err(VpnError::HandshakeFailed(
                "Handshake timeout - server may be unreachable or blocked".to_string(),
            )),
        }
    }

    /// Spawn outbound packet processing task (adapter -> server)
    fn spawn_outbound_task(
        &self,
        adapter: Arc<WintunAdapter>,
        tunn: Arc<std::sync::Mutex<Tunn>>,
        socket: Arc<UdpSocket>,
        running: Arc<AtomicBool>,
        stats: Arc<std::sync::Mutex<TunnelStats>>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut encrypt_buf = vec![0u8; MAX_PACKET_SIZE];

            while running.load(Ordering::SeqCst) {
                // Check for shutdown
                if shutdown.try_recv().is_ok() {
                    break;
                }

                // Read packet from adapter (this blocks)
                let packet = match adapter.receive_packet() {
                    Some(p) => p,
                    None => {
                        // Shutdown signal received
                        break;
                    }
                };

                let packet_data = packet.bytes();

                // Encrypt packet
                let encrypted = {
                    let mut tunn = tunn.lock().unwrap();
                    tunn.encapsulate(packet_data, &mut encrypt_buf)
                };

                match encrypted {
                    TunnResult::WriteToNetwork(data) => {
                        if let Err(e) = socket.send(data).await {
                            log::error!("Failed to send encrypted packet: {}", e);
                            continue;
                        }

                        // Update stats
                        if let Ok(mut s) = stats.lock() {
                            s.bytes_sent += data.len() as u64;
                            s.packets_sent += 1;
                        }
                    }
                    TunnResult::Done => {
                        // Packet was handled internally (e.g., keepalive)
                    }
                    TunnResult::Err(e) => {
                        log::error!("Encryption error: {:?}", e);
                    }
                    _ => {}
                }
            }

            log::info!("Outbound task stopped");
        })
    }

    /// Spawn inbound packet processing task (server -> adapter)
    ///
    /// When inbound_handler is set (split tunnel mode), decrypted packets are
    /// passed to the handler instead of being written to the Wintun adapter.
    fn spawn_inbound_task(
        &self,
        adapter: Arc<WintunAdapter>,
        tunn: Arc<std::sync::Mutex<Tunn>>,
        socket: Arc<UdpSocket>,
        running: Arc<AtomicBool>,
        stats: Arc<std::sync::Mutex<TunnelStats>>,
        inbound_handler: Arc<std::sync::Mutex<Option<InboundHandler>>>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut recv_buf = vec![0u8; MAX_PACKET_SIZE];
            let mut decrypt_buf = vec![0u8; MAX_PACKET_SIZE];
            let mut handler_used = false;

            while running.load(Ordering::SeqCst) {
                // Check for shutdown
                if shutdown.try_recv().is_ok() {
                    break;
                }

                // Receive from server with timeout
                let recv_result = tokio::time::timeout(
                    Duration::from_millis(100),
                    socket.recv(&mut recv_buf),
                )
                .await;

                let n = match recv_result {
                    Ok(Ok(n)) => {
                        log::debug!("Inbound: received {} bytes from VPN server", n);
                        n
                    }
                    Ok(Err(e)) => {
                        log::error!("Receive error: {}", e);
                        continue;
                    }
                    Err(_) => {
                        // Timeout, check running flag
                        continue;
                    }
                };

                // Decrypt packet
                let decrypted = {
                    let mut tunn = tunn.lock().unwrap();
                    tunn.decapsulate(None, &recv_buf[..n], &mut decrypt_buf)
                };

                log::debug!("Inbound: decapsulate result: {:?}", match &decrypted {
                    TunnResult::WriteToTunnelV4(d, _) => format!("WriteToTunnelV4({} bytes)", d.len()),
                    TunnResult::WriteToTunnelV6(d, _) => format!("WriteToTunnelV6({} bytes)", d.len()),
                    TunnResult::WriteToNetwork(d) => format!("WriteToNetwork({} bytes)", d.len()),
                    TunnResult::Done => "Done".to_string(),
                    TunnResult::Err(e) => format!("Err({:?})", e),
                });

                match decrypted {
                    TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                        let len = data.len();

                        // Check if we have an inbound handler (split tunnel mode)
                        let handler_opt = inbound_handler.lock().ok().and_then(|g| g.clone());

                        if let Some(handler) = handler_opt {
                            // Split tunnel mode: pass to handler for injection to physical adapter
                            if !handler_used {
                                log::info!("Inbound task: using split tunnel handler for packet delivery");
                                handler_used = true;
                            }
                            handler(data);

                            // Update stats
                            if let Ok(mut s) = stats.lock() {
                                s.bytes_received += len as u64;
                                s.packets_received += 1;
                            }
                        } else {
                            // Normal mode: write directly to Wintun adapter
                            if let Ok(mut send_packet) = adapter.allocate_send_packet(len as u16) {
                                send_packet.bytes_mut().copy_from_slice(data);
                                adapter.send_packet(send_packet);

                                // Update stats
                                if let Ok(mut s) = stats.lock() {
                                    s.bytes_received += len as u64;
                                    s.packets_received += 1;
                                }
                            }
                        }
                    }
                    TunnResult::WriteToNetwork(data) => {
                        // Send response (e.g., handshake, keepalive)
                        if let Err(e) = socket.send(data).await {
                            log::error!("Failed to send response: {}", e);
                        }
                    }
                    TunnResult::Done => {
                        // Internal handling complete
                    }
                    TunnResult::Err(e) => {
                        log::warn!("Decryption error: {:?}", e);
                    }
                }
            }

            log::info!("Inbound task stopped");
        })
    }

    /// Spawn timer/keepalive task
    ///
    /// CRITICAL: BoringTun requires `update_timers()` to be called every ~100ms
    /// to properly handle:
    /// - Handshake initiation and completion
    /// - Keepalive packet generation
    /// - Connection timeout detection
    fn spawn_keepalive_task(
        &self,
        tunn: Arc<std::sync::Mutex<Tunn>>,
        socket: Arc<UdpSocket>,
        running: Arc<AtomicBool>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            // Use 100ms tick interval for BoringTun timer management
            let tick_interval = Duration::from_millis(TICK_INTERVAL_MS);

            while running.load(Ordering::SeqCst) {
                tokio::select! {
                    _ = tokio::time::sleep(tick_interval) => {
                        // Call update_timers to handle handshakes, keepalives, timeouts
                        let result = {
                            let mut tunn = tunn.lock().unwrap();
                            tunn.update_timers(&mut buf)
                        };

                        match result {
                            TunnResult::WriteToNetwork(data) => {
                                if let Err(e) = socket.send(data).await {
                                    log::warn!("Failed to send timer packet: {}", e);
                                } else {
                                    log::trace!("Timer packet sent ({} bytes)", data.len());
                                }
                            }
                            TunnResult::Err(e) => {
                                log::error!("BoringTun timer error: {:?}", e);
                            }
                            TunnResult::Done => {
                                // No action needed this tick
                            }
                            _ => {}
                        }
                    }
                    _ = shutdown.recv() => {
                        break;
                    }
                }
            }

            log::info!("Timer/keepalive task stopped");
        })
    }

    /// Stop the tunnel
    pub fn stop(&self) {
        log::info!("Stopping WireGuard tunnel");
        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if tunnel is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get tunnel statistics
    pub fn stats(&self) -> TunnelStats {
        self.stats.lock().unwrap().clone()
    }

    /// Get the server endpoint
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// Get the config
    pub fn config(&self) -> &VpnConfig {
        &self.config
    }
}

impl Drop for WireguardTunnel {
    fn drop(&mut self) {
        self.stop();
    }
}
