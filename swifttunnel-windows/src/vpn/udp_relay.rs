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
const READ_TIMEOUT: Duration = Duration::from_millis(10);

/// Grace period after relay switch: accept packets from BOTH old and new relay.
/// This eliminates the inbound blackout while the new relay establishes session.
const RELAY_SWITCH_GRACE_PERIOD: Duration = Duration::from_secs(2);

/// UDP Relay client for Game Booster mode
pub struct UdpRelay {
    /// Socket for communicating with relay server
    socket: UdpSocket,
    /// Relay server address (swappable for auto-routing)
    relay_addr: ArcSwap<SocketAddr>,
    /// Previous relay address — accepted during grace period after switch
    previous_relay_addr: ArcSwap<Option<SocketAddr>>,
    /// When the last relay switch occurred (for grace period calculation)
    switch_time: ArcSwap<Option<Instant>>,
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
            previous_relay_addr: ArcSwap::from_pointee(None),
            switch_time: ArcSwap::from_pointee(None),
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
    /// After an auto-routing relay switch, packets from the OLD relay are accepted
    /// during a 2-second grace period. This eliminates the inbound blackout that
    /// occurs while the new relay establishes the game server session mapping.
    pub fn receive_inbound(&self, buffer: &mut [u8]) -> Result<Option<usize>> {
        // Temporary buffer to receive with session ID
        let mut recv_buf = [0u8; 1600];

        match self.socket.recv_from(&mut recv_buf) {
            Ok((len, from)) => {
                // Verify it's from our relay server (current or previous during grace period)
                let expected_addr = **self.relay_addr.load();
                if from != expected_addr {
                    // Check if within grace period for previous relay
                    let in_grace = if let (Some(prev), Some(switched_at)) =
                        ((**self.previous_relay_addr.load()).as_ref(), (**self.switch_time.load()).as_ref())
                    {
                        from == *prev && switched_at.elapsed() < RELAY_SWITCH_GRACE_PERIOD
                    } else {
                        false
                    };

                    if !in_grace {
                        log::warn!("UDP Relay: Received packet from unexpected source {} (expected {})", from, expected_addr);
                        return Ok(None);
                    }
                    log::trace!("UDP Relay: Accepting packet from previous relay {} (grace period)", from);
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

    /// Send an immediate keepalive (session_id-only packet) to the current relay.
    /// Used after auto-routing switch to establish session on the new relay ASAP.
    pub fn send_keepalive_now(&self) -> Result<()> {
        let current_addr = **self.relay_addr.load();
        self.socket.send_to(&self.session_id, current_addr)
            .context("Failed to send immediate keepalive")?;
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = Instant::now();
        }
        log::info!("UDP Relay: Sent immediate keepalive to {} (session {:016x})", current_addr, self.session_id_u64());
        Ok(())
    }

    /// Send a burst of keepalives to quickly establish NAT mapping and relay session.
    /// Sends 3 keepalives at 0ms, 50ms, 100ms spacing to punch through NAT/firewalls
    /// faster than a single packet. Used after auto-routing relay switch.
    pub fn send_keepalive_burst(&self) -> Result<()> {
        let current_addr = **self.relay_addr.load();
        for i in 0..3 {
            if i > 0 {
                std::thread::sleep(Duration::from_millis(50));
            }
            match self.socket.send_to(&self.session_id, current_addr) {
                Ok(_) => {}
                Err(e) if i == 0 => return Err(e.into()),
                Err(e) => {
                    log::warn!("UDP Relay: Keepalive burst #{} failed: {}", i + 1, e);
                }
            }
        }
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = Instant::now();
        }
        log::info!(
            "UDP Relay: Sent keepalive burst (3 packets) to {} (session {:016x})",
            current_addr, self.session_id_u64()
        );
        Ok(())
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
    /// Stores the old address so receive_inbound() can accept packets from both
    /// relays during a grace period, eliminating the inbound blackout.
    pub fn switch_relay(&self, new_addr: SocketAddr) {
        let old_addr = **self.relay_addr.load();
        self.previous_relay_addr.store(Arc::new(Some(old_addr)));
        self.switch_time.store(Arc::new(Some(Instant::now())));
        self.relay_addr.store(Arc::new(new_addr));
        log::info!(
            "UDP Relay: Switched relay {} -> {} (session {:016x}, grace period {}s)",
            old_addr, new_addr, self.session_id_u64(), RELAY_SWITCH_GRACE_PERIOD.as_secs()
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
