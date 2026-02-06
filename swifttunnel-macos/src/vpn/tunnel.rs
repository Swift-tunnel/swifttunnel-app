//! WireGuard Tunnel Implementation using BoringTun (macOS)
//!
//! This module implements the WireGuard protocol using BoringTun (Cloudflare's
//! userspace WireGuard implementation). It handles:
//! - Noise protocol handshake
//! - Packet encryption/decryption
//! - Keepalive management
//! - Bidirectional packet routing via utun
//!
//! Performance note: Uses parking_lot::Mutex for the shared Tunn instance
//! to minimize contention when multiple worker threads encrypt packets.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use boringtun::noise::{Tunn, TunnResult};
use super::adapter::UtunAdapter;
use super::config::parse_key;
use super::{VpnError, VpnResult};
use crate::auth::types::VpnConfig;

/// Fast mutex for WireGuard encryption (avoids std::sync::Mutex contention)
pub use parking_lot::Mutex as FastMutex;

/// WireGuard keepalive interval in seconds (sent to peer)
const KEEPALIVE_INTERVAL: u16 = 25;

/// BoringTun tick interval in milliseconds (for internal timer management)
/// Must be called frequently to handle handshakes, keepalives, and timeouts
/// 50ms balances responsiveness with CPU efficiency (was 100ms)
const TICK_INTERVAL_MS: u64 = 50;

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
    /// If set, decrypted packets are passed to this handler instead of utun
    inbound_handler: Arc<std::sync::Mutex<Option<InboundHandler>>>,
    /// Shared Tunn instance for direct encryption by split tunnel workers
    /// Uses parking_lot::Mutex (FastMutex) to minimize contention under load
    tunn: Arc<std::sync::Mutex<Option<Arc<FastMutex<Tunn>>>>>,
    /// When true, suppress keepalives from tunnel socket (split tunnel handles them)
    skip_keepalives: Arc<AtomicBool>,
    /// When true, the tunnel's inbound task should stop reading (split tunnel handles inbound)
    skip_inbound: Arc<AtomicBool>,
    /// Synchronization flag for socket handoff to split tunnel.
    inbound_task_stopped: Arc<AtomicBool>,
    /// Stored std socket clone for split tunnel handoff
    stored_socket: Arc<std::sync::Mutex<Option<std::net::UdpSocket>>>,
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
            tunn: Arc::new(std::sync::Mutex::new(None)),
            skip_keepalives: Arc::new(AtomicBool::new(false)),
            skip_inbound: Arc::new(AtomicBool::new(false)),
            inbound_task_stopped: Arc::new(AtomicBool::new(true)),
            stored_socket: Arc::new(std::sync::Mutex::new(None)),
        })
    }

    /// Set the inbound packet handler for split tunnel mode
    pub fn set_inbound_handler(&self, handler: InboundHandler) {
        log::info!("Setting inbound packet handler for split tunnel");
        *self.inbound_handler.lock().unwrap() = Some(handler);
        self.skip_keepalives.store(true, Ordering::SeqCst);
        log::info!("Disabled tunnel keepalives (split tunnel mode active)");
    }

    /// Disable or enable keepalives from the tunnel socket
    pub fn set_skip_keepalives(&self, skip: bool) {
        self.skip_keepalives.store(skip, Ordering::SeqCst);
        log::info!("Tunnel keepalives: {}", if skip { "DISABLED" } else { "enabled" });
    }

    /// Get the inbound handler (for passing to tasks)
    fn get_inbound_handler(&self) -> Arc<std::sync::Mutex<Option<InboundHandler>>> {
        Arc::clone(&self.inbound_handler)
    }

    /// Get the Tunn instance for direct encryption by split tunnel workers
    pub fn get_tunn(&self) -> Option<Arc<FastMutex<Tunn>>> {
        self.tunn.lock().unwrap().clone()
    }

    /// Get the UDP socket for split tunnel reuse
    ///
    /// Returns the socket that performed the WireGuard handshake.
    /// This method TAKES the socket (Option::take), so it can only be called once.
    pub fn take_socket_for_split_tunnel(&self) -> Option<std::net::UdpSocket> {
        log::info!("========================================");
        log::info!("SOCKET HANDOFF TO SPLIT TUNNEL");
        log::info!("========================================");

        let socket = self.stored_socket.lock().unwrap().take();
        if let Some(ref sock) = socket {
            log::info!("  Socket: {:?}", sock.local_addr());
            log::info!("  Step 1: Signaling inbound task to stop...");

            self.skip_inbound.store(true, Ordering::SeqCst);

            log::info!("  Step 2: Waiting for inbound task to confirm exit...");
            let start = std::time::Instant::now();
            let max_wait = std::time::Duration::from_millis(300);
            while !self.inbound_task_stopped.load(Ordering::SeqCst) {
                if start.elapsed() > max_wait {
                    log::error!("TIMEOUT: Inbound task did not stop in {}ms!", max_wait.as_millis());
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }

            let elapsed = start.elapsed();
            if self.inbound_task_stopped.load(Ordering::SeqCst) {
                log::info!("  Step 3: Inbound task CONFIRMED stopped ({}ms)", elapsed.as_millis());
                log::info!("  Socket handoff SUCCESSFUL");
            }
            log::info!("========================================");
        } else {
            log::error!("SOCKET HANDOFF FAILED - no socket available!");
        }
        socket
    }

    /// Get the VPN server endpoint
    pub fn get_endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// Start the tunnel packet processing loops
    ///
    /// This spawns two async tasks:
    /// 1. Outbound: utun adapter -> encrypt -> UDP to server
    /// 2. Inbound: UDP from server -> decrypt -> utun adapter
    pub async fn start(&self, adapter: Arc<UtunAdapter>) -> VpnResult<()> {
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

        // Wrap in FastMutex (parking_lot) for low contention under load
        let tunn = Arc::new(FastMutex::new(tunn));

        // Store tunn for external access (split tunnel direct encryption)
        *self.tunn.lock().unwrap() = Some(Arc::clone(&tunn));

        // Create UDP socket for server communication
        let std_socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| VpnError::Network(format!("Failed to bind UDP socket: {}", e)))?;

        std_socket
            .connect(self.endpoint)
            .map_err(|e| VpnError::Network(format!("Failed to connect to endpoint: {}", e)))?;

        // Set socket receive buffer to 256KB for low-latency gaming traffic
        // On macOS, use setsockopt via libc
        unsafe {
            let buf_size: libc::c_int = 256 * 1024;
            let _ = libc::setsockopt(
                std::os::unix::io::AsRawFd::as_raw_fd(&std_socket) as libc::c_int,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &buf_size as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        // Clone the socket BEFORE converting to Tokio - this clone will be used by split tunnel
        let socket_for_split_tunnel = std_socket.try_clone()
            .map_err(|e| VpnError::Network(format!("Failed to clone socket for split tunnel: {}", e)))?;

        *self.stored_socket.lock().unwrap() = Some(socket_for_split_tunnel);
        let local_addr = std_socket.local_addr().ok();
        log::info!("========================================");
        log::info!("VPN SOCKET CREATED");
        log::info!("  Local: {:?}", local_addr);
        log::info!("  Remote: {}", self.endpoint);
        log::info!("  Socket cloned for split tunnel handoff");
        log::info!("========================================");

        // Set non-blocking mode for Tokio conversion
        std_socket.set_nonblocking(true)
            .map_err(|e| VpnError::Network(format!("Failed to set socket non-blocking: {}", e)))?;

        // Convert to Tokio socket for async tasks
        let socket = UdpSocket::from_std(std_socket)
            .map_err(|e| VpnError::Network(format!("Failed to convert socket to Tokio: {}", e)))?;

        let socket = Arc::new(socket);

        self.running.store(true, Ordering::SeqCst);

        // Perform initial handshake
        self.initiate_handshake(&tunn, &socket).await?;

        // Create channel for shutdown coordination
        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

        // Spawn outbound task (utun adapter -> server)
        let outbound_handle = self.spawn_outbound_task(
            Arc::clone(&adapter),
            Arc::clone(&tunn),
            Arc::clone(&socket),
            Arc::clone(&self.running),
            Arc::clone(&self.stats),
            shutdown_tx.subscribe(),
        );

        // Spawn inbound task (server -> utun adapter)
        self.inbound_task_stopped.store(false, Ordering::SeqCst);
        let inbound_handle = self.spawn_inbound_task(
            Arc::clone(&adapter),
            Arc::clone(&tunn),
            Arc::clone(&socket),
            Arc::clone(&self.running),
            Arc::clone(&self.stats),
            self.get_inbound_handler(),
            Arc::clone(&self.skip_inbound),
            Arc::clone(&self.inbound_task_stopped),
            shutdown_tx.subscribe(),
        );

        // Spawn keepalive task
        let keepalive_handle = self.spawn_keepalive_task(
            Arc::clone(&tunn),
            Arc::clone(&socket),
            Arc::clone(&self.running),
            Arc::clone(&self.skip_keepalives),
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
        tunn: &Arc<FastMutex<Tunn>>,
        socket: &Arc<UdpSocket>,
    ) -> VpnResult<()> {
        log::info!("Initiating WireGuard handshake");

        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        // Get handshake initiation packet
        let handshake_init = {
            let mut tunn = tunn.lock();
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
                    let mut tunn = tunn.lock();
                    let decap_result = tunn.decapsulate(None, &response_buf[..n], &mut buf);
                    match decap_result {
                        TunnResult::WriteToNetwork(data) => {
                            Some(data.to_vec())
                        }
                        other => {
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

    /// Spawn outbound packet processing task (utun adapter -> server)
    ///
    /// Reads IP packets from the utun device asynchronously, encrypts them
    /// with WireGuard, and sends to the VPN server.
    fn spawn_outbound_task(
        &self,
        adapter: Arc<UtunAdapter>,
        tunn: Arc<FastMutex<Tunn>>,
        socket: Arc<UdpSocket>,
        running: Arc<AtomicBool>,
        stats: Arc<std::sync::Mutex<TunnelStats>>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut read_buf = vec![0u8; MAX_PACKET_SIZE];
            let mut encrypt_buf = vec![0u8; MAX_PACKET_SIZE];
            let device = adapter.device();

            while running.load(Ordering::SeqCst) {
                if shutdown.try_recv().is_ok() {
                    break;
                }

                // Read packet from utun device (async)
                let read_result = tokio::time::timeout(
                    Duration::from_millis(100),
                    device.recv(&mut read_buf),
                ).await;

                let n = match read_result {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => {
                        if running.load(Ordering::SeqCst) {
                            log::error!("utun read error: {}", e);
                        }
                        continue;
                    }
                    Err(_) => {
                        // Timeout, check running flag
                        continue;
                    }
                };

                let packet_data = &read_buf[..n];

                // Encrypt packet
                let encrypted = {
                    let mut tunn = tunn.lock();
                    tunn.encapsulate(packet_data, &mut encrypt_buf)
                };

                match encrypted {
                    TunnResult::WriteToNetwork(data) => {
                        if let Err(e) = socket.send(data).await {
                            log::error!("Failed to send encrypted packet: {}", e);
                            continue;
                        }

                        if let Ok(mut s) = stats.lock() {
                            s.bytes_sent += data.len() as u64;
                            s.packets_sent += 1;
                        }
                    }
                    TunnResult::Done => {}
                    TunnResult::Err(e) => {
                        log::error!("Encryption error: {:?}", e);
                    }
                    _ => {}
                }
            }

            log::info!("Outbound task stopped");
        })
    }

    /// Spawn inbound packet processing task (server -> utun adapter)
    ///
    /// When inbound_handler is set (split tunnel mode), decrypted packets are
    /// passed to the handler instead of being written to the utun adapter.
    fn spawn_inbound_task(
        &self,
        adapter: Arc<UtunAdapter>,
        tunn: Arc<FastMutex<Tunn>>,
        socket: Arc<UdpSocket>,
        running: Arc<AtomicBool>,
        stats: Arc<std::sync::Mutex<TunnelStats>>,
        inbound_handler: Arc<std::sync::Mutex<Option<InboundHandler>>>,
        skip_inbound: Arc<AtomicBool>,
        inbound_task_stopped: Arc<AtomicBool>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut recv_buf = vec![0u8; MAX_PACKET_SIZE];
            let mut decrypt_buf = vec![0u8; MAX_PACKET_SIZE];
            let mut handler_used = false;
            let mut packet_count: u64 = 0;
            let device = adapter.device();

            while running.load(Ordering::SeqCst) {
                // Check if split tunnel has taken over inbound handling
                if skip_inbound.load(Ordering::SeqCst) {
                    log::info!("Inbound task: split tunnel took over - stopping");
                    break;
                }

                if shutdown.try_recv().is_ok() {
                    break;
                }

                // Receive from server with timeout
                let recv_result = tokio::time::timeout(
                    Duration::from_millis(100),
                    socket.recv(&mut recv_buf),
                ).await;

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
                        continue;
                    }
                };

                // Decrypt packet
                let decrypted = {
                    let mut tunn = tunn.lock();
                    tunn.decapsulate(None, &recv_buf[..n], &mut decrypt_buf)
                };

                let result_desc = match &decrypted {
                    TunnResult::WriteToTunnelV4(d, _) => format!("WriteToTunnelV4({} bytes)", d.len()),
                    TunnResult::WriteToTunnelV6(d, _) => format!("WriteToTunnelV6({} bytes)", d.len()),
                    TunnResult::WriteToNetwork(d) => format!("WriteToNetwork({} bytes)", d.len()),
                    TunnResult::Done => "Done".to_string(),
                    TunnResult::Err(e) => format!("Err({:?})", e),
                };
                packet_count += 1;
                if packet_count <= 10 || packet_count % 100 == 0 {
                    log::info!("Tunnel inbound #{}: {} (received {} encrypted bytes)", packet_count, result_desc, n);
                }

                match decrypted {
                    TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                        let len = data.len();

                        let handler_opt = inbound_handler.lock().ok().and_then(|g| g.clone());

                        if let Some(handler) = handler_opt {
                            // Split tunnel mode: pass to handler
                            if !handler_used {
                                log::info!("Inbound task: using split tunnel handler for packet delivery");
                                handler_used = true;
                            }
                            handler(data);

                            if let Ok(mut s) = stats.lock() {
                                s.bytes_received += len as u64;
                                s.packets_received += 1;
                            }
                        } else {
                            // Normal mode: write to utun device
                            // tun-rs send() is async - we need to copy the data since
                            // decrypt_buf will be reused
                            let packet_copy = data.to_vec();
                            if let Err(e) = device.send(&packet_copy).await {
                                log::error!("Failed to write to utun: {}", e);
                            } else if let Ok(mut s) = stats.lock() {
                                s.bytes_received += len as u64;
                                s.packets_received += 1;
                            }
                        }
                    }
                    TunnResult::WriteToNetwork(data) => {
                        if let Err(e) = socket.send(data).await {
                            log::error!("Failed to send response: {}", e);
                        }
                    }
                    TunnResult::Done => {}
                    TunnResult::Err(e) => {
                        log::warn!("Decryption error: {:?}", e);
                    }
                }
            }

            inbound_task_stopped.store(true, Ordering::SeqCst);
            log::info!("Inbound task stopped (signaled via inbound_task_stopped flag)");
        })
    }

    /// Spawn timer/keepalive task
    fn spawn_keepalive_task(
        &self,
        tunn: Arc<FastMutex<Tunn>>,
        socket: Arc<UdpSocket>,
        running: Arc<AtomicBool>,
        skip_keepalives: Arc<AtomicBool>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            let tick_interval = Duration::from_millis(TICK_INTERVAL_MS);
            let mut skip_logged = false;

            while running.load(Ordering::SeqCst) {
                tokio::select! {
                    _ = tokio::time::sleep(tick_interval) => {
                        let should_skip = skip_keepalives.load(Ordering::SeqCst);

                        if should_skip {
                            if !skip_logged {
                                log::info!("Tunnel timer task: split tunnel mode - delegating to inbound receiver");
                                skip_logged = true;
                            }
                            continue;
                        }

                        let result = {
                            let mut tunn = tunn.lock();
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
                            TunnResult::Done => {}
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
