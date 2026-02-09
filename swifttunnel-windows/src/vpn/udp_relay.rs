//! V3 Game Booster Mode - Unencrypted UDP Relay
//!
//! Similar to ExitLag/WTFast - routes game traffic through optimized paths
//! without encryption overhead. Trades security for performance.
//!
//! Protocol:
//! - Client sends: [8-byte session_id][original UDP payload]
//! - Server forwards payload to game server, tracks session for responses
//! - Server sends back: [8-byte session_id][game server response]
//! - Client strips session_id and injects response to game

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::{Result, Context};
use arc_swap::ArcSwap;

/// Session ID length in bytes
const SESSION_ID_LEN: usize = 8;

/// Maximum payload size for relay packets
/// Allow full IP packets (up to 1500 bytes) to avoid silently dropping large game packets.
/// Packets that cause the outer UDP datagram to exceed path MTU will be IP-fragmented
/// by the OS, which is preferable to silent drops that cause Roblox Error 277.
const MAX_PAYLOAD_SIZE: usize = 1500;

/// Keepalive interval to maintain NAT bindings - 15s is safer for strict NATs
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Read timeout - shorter for tighter packet pickup loop
const READ_TIMEOUT: Duration = Duration::from_micros(100);

/// UDP Relay client for Game Booster mode
pub struct UdpRelay {
    /// Socket for communicating with relay server
    socket: UdpSocket,
    /// Relay server address (swappable for auto-routing)
    relay_addr: ArcSwap<SocketAddr>,
    /// Unique session ID for this connection
    session_id: [u8; SESSION_ID_LEN],
    /// Stop flag
    stop_flag: Arc<AtomicBool>,
    /// Packets sent counter
    packets_sent: AtomicU64,
    /// Packets received counter
    packets_received: AtomicU64,
    /// Last activity time for keepalive
    last_activity: std::sync::Mutex<Instant>,
}

impl UdpRelay {
    /// Create a new UDP relay connection to the specified server
    ///
    /// relay_addr should already be resolved (use tokio::net::lookup_host for DNS)
    pub fn new(relay_addr: SocketAddr) -> Result<Self> {

        // Bind to any available port
        let socket = UdpSocket::bind("0.0.0.0:0")
            .context("Failed to bind UDP socket")?;

        // Set socket options for low latency
        socket.set_read_timeout(Some(READ_TIMEOUT))
            .context("Failed to set read timeout")?;

        // Increase send and receive buffers to 256KB to handle burst traffic
        // Default Windows SO_SNDBUF is only 8KB which causes WouldBlock under
        // Roblox's 30-60 packets/sec rate, leading to silent packet drops (Error 277)
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            let raw = socket.as_raw_socket();
            let buf_size: i32 = 256 * 1024;
            let sock = windows::Win32::Networking::WinSock::SOCKET(raw as usize);

            unsafe {
                let buf_bytes = std::slice::from_raw_parts(
                    &buf_size as *const i32 as *const u8,
                    4,
                );

                let result = windows::Win32::Networking::WinSock::setsockopt(
                    sock,
                    windows::Win32::Networking::WinSock::SOL_SOCKET,
                    windows::Win32::Networking::WinSock::SO_RCVBUF,
                    Some(buf_bytes),
                );
                if result != 0 {
                    log::warn!("UDP Relay: Failed to set SO_RCVBUF to 256KB, using default");
                }

                let result = windows::Win32::Networking::WinSock::setsockopt(
                    sock,
                    windows::Win32::Networking::WinSock::SOL_SOCKET,
                    windows::Win32::Networking::WinSock::SO_SNDBUF,
                    Some(buf_bytes),
                );
                if result != 0 {
                    log::warn!("UDP Relay: Failed to set SO_SNDBUF to 256KB, using default");
                }
            }
        }

        // Generate random session ID
        let mut session_id = [0u8; SESSION_ID_LEN];
        getrandom(&mut session_id);

        log::info!(
            "UDP Relay: Created session {:016x} to {}",
            u64::from_be_bytes(session_id),
            relay_addr
        );

        Ok(Self {
            socket,
            relay_addr: ArcSwap::from_pointee(relay_addr),
            session_id,
            stop_flag: Arc::new(AtomicBool::new(false)),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            last_activity: std::sync::Mutex::new(Instant::now()),
        })
    }

    /// Get the session ID as a u64 for logging
    pub fn session_id_u64(&self) -> u64 {
        u64::from_be_bytes(self.session_id)
    }

    /// Get the stop flag for external control
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop_flag)
    }

    /// Forward a packet through the relay (outbound: game client -> relay -> game server)
    ///
    /// Takes the original UDP payload and prepends session ID before sending to relay
    /// Includes retry logic for transient send failures
    pub fn forward_outbound(&self, payload: &[u8]) -> Result<usize> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            log::warn!("UDP Relay: Packet too large ({} > {}), dropping", payload.len(), MAX_PAYLOAD_SIZE);
            return Ok(0);
        }

        // Build packet: [session_id][payload] on the stack (no heap alloc)
        let total_len = SESSION_ID_LEN + payload.len();
        let mut packet = [0u8; SESSION_ID_LEN + 1500];
        packet[..SESSION_ID_LEN].copy_from_slice(&self.session_id);
        packet[SESSION_ID_LEN..total_len].copy_from_slice(payload);

        // Try to send, retry once on WouldBlock
        let current_addr = **self.relay_addr.load();
        let sent = match self.socket.send_to(&packet[..total_len], current_addr) {
            Ok(sent) => sent,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Retry once after tiny delay
                std::thread::sleep(Duration::from_micros(50));
                self.socket.send_to(&packet[..total_len], current_addr)
                    .context("Retry send failed")?
            }
            Err(e) => return Err(e.into()),
        };

        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = Instant::now();
        }

        Ok(sent)
    }

    /// Receive a packet from the relay (inbound: game server -> relay -> game client)
    ///
    /// Returns the payload with session ID stripped, or None if no packet available.
    ///
    /// NOTE: After an auto-routing relay switch, in-flight response packets from the
    /// OLD relay server will be dropped here (source address validation fails).
    /// This is expected and acceptable - games handle transient packet loss gracefully.
    pub fn receive_inbound(&self, buffer: &mut [u8]) -> Result<Option<usize>> {
        // Temporary buffer to receive with session ID
        let mut recv_buf = [0u8; 1600];

        match self.socket.recv_from(&mut recv_buf) {
            Ok((len, from)) => {
                // Verify it's from our relay server
                let expected_addr = **self.relay_addr.load();
                if from != expected_addr {
                    log::warn!("UDP Relay: Received packet from unexpected source {}", from);
                    return Ok(None);
                }

                // Must have at least session ID
                if len < SESSION_ID_LEN {
                    log::warn!("UDP Relay: Received packet too small ({})", len);
                    return Ok(None);
                }

                // Verify session ID matches
                if &recv_buf[..SESSION_ID_LEN] != &self.session_id {
                    log::warn!("UDP Relay: Session ID mismatch, ignoring packet");
                    return Ok(None);
                }

                // Extract payload (skip session ID)
                let payload_len = len - SESSION_ID_LEN;
                if payload_len > buffer.len() {
                    log::warn!("UDP Relay: Buffer too small for payload");
                    return Ok(None);
                }

                buffer[..payload_len].copy_from_slice(&recv_buf[SESSION_ID_LEN..len]);
                self.packets_received.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut guard) = self.last_activity.lock() {
                    *guard = Instant::now();
                }

                Ok(Some(payload_len))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Send keepalive to maintain NAT binding
    pub fn send_keepalive(&self) -> Result<()> {
        let should_send = self.last_activity
            .lock()
            .map(|guard| guard.elapsed() >= KEEPALIVE_INTERVAL)
            .unwrap_or(true); // If poisoned, send keepalive anyway

        if should_send {
            // Send empty payload with just session ID
            let current_addr = **self.relay_addr.load();
            self.socket.send_to(&self.session_id, current_addr)
                .context("Failed to send keepalive")?;
            if let Ok(mut guard) = self.last_activity.lock() {
                *guard = Instant::now();
            }
            log::trace!("UDP Relay: Sent keepalive");
        }
        Ok(())
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64) {
        (
            self.packets_sent.load(Ordering::Relaxed),
            self.packets_received.load(Ordering::Relaxed),
        )
    }

    /// Stop the relay
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Release);
        log::info!(
            "UDP Relay: Stopped session {:016x} (sent: {}, recv: {})",
            self.session_id_u64(),
            self.packets_sent.load(Ordering::Relaxed),
            self.packets_received.load(Ordering::Relaxed)
        );
    }

    /// Clone the socket for use in inbound receiver thread
    pub fn try_clone_socket(&self) -> Result<UdpSocket> {
        self.socket.try_clone().context("Failed to clone relay socket")
    }

    /// Get the relay server address
    pub fn relay_addr(&self) -> SocketAddr {
        **self.relay_addr.load()
    }

    /// Atomically switch to a new relay server address.
    /// The next outbound packet will go to the new address.
    /// This is the core of Auto Routing - zero-disruption server switching.
    pub fn switch_relay(&self, new_addr: SocketAddr) {
        let old_addr = **self.relay_addr.load();
        self.relay_addr.store(Arc::new(new_addr));
        log::info!(
            "UDP Relay: Switched relay {} -> {} (session {:016x})",
            old_addr, new_addr, self.session_id_u64()
        );
    }

    /// Get session ID bytes
    pub fn session_id_bytes(&self) -> &[u8; SESSION_ID_LEN] {
        &self.session_id
    }
}

impl Drop for UdpRelay {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Generate random bytes using the rand crate
fn getrandom(buf: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(buf);
}

/// Context for relay mode in ParallelInterceptor
pub struct RelayContext {
    pub relay: Arc<UdpRelay>,
    pub session_id: [u8; SESSION_ID_LEN],
}

impl RelayContext {
    pub fn new(relay: Arc<UdpRelay>) -> Self {
        let session_id = *relay.session_id_bytes();
        Self { relay, session_id }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_generation() {
        let mut id1 = [0u8; 8];
        let mut id2 = [0u8; 8];
        getrandom(&mut id1);
        getrandom(&mut id2);
        // Should be different (with extremely high probability)
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_packet_format() {
        // Session ID is 8 bytes, so a 100-byte payload becomes 108 bytes
        let session_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let payload = [0u8; 100];

        let mut packet = Vec::new();
        packet.extend_from_slice(&session_id);
        packet.extend_from_slice(&payload);

        assert_eq!(packet.len(), 108);
        assert_eq!(&packet[..8], &session_id);
    }
}
