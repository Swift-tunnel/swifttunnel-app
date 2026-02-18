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

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Session ID length in bytes
const SESSION_ID_LEN: usize = 8;
const UDP_HEADER_LEN: usize = 8;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const AUTH_HELLO_FRAME_TYPE: u8 = 0xA1;
const AUTH_ACK_FRAME_TYPE: u8 = 0xA2;
// Slightly longer handshake budget improves reliability on congested/PPPoE paths
// without affecting steady-state packet latency.
const AUTH_HANDSHAKE_TOTAL_TIMEOUT: Duration = Duration::from_millis(1500);
const AUTH_HANDSHAKE_RETRY_DELAY: Duration = Duration::from_millis(250);
const AUTH_HANDSHAKE_ATTEMPTS: usize = 4;

/// Outer path MTU for relay packets (client <-> relay).
///
/// The tunneled payload is an *inner IPv4 packet* captured at NDIS layer. We then add:
/// - 8 bytes session id (relay framing)
/// - outer UDP header (8 bytes)
/// - outer IP header (20 bytes for IPv4)
///
/// If Roblox (RakNet) negotiates ~1492-byte packets, adding our encapsulation overhead pushes
/// the *outer* datagram over 1500, causing IP fragmentation on the client->relay path.
/// Fragmented UDP is frequently dropped, and that can manifest as Roblox Error 279/277 during
/// the connection handshake.
///
/// We avoid this by capping the inner packet length so the outer datagram stays <= 1500.
///
/// Note: 1500 is a *cap*, not a guarantee. If the user's active interface MTU is lower
/// (PPPoE 1492, user-applied MTU boost, etc.), sending 1500-byte outer datagrams forces
/// IP fragmentation. Fragmented UDP is frequently dropped.
///
/// On Windows we periodically refresh the effective MTU from the OS route/interface
/// to the current relay endpoint, and clamp to that value (still capped at 1500).
const RELAY_PATH_MTU_UPPER_BOUND: usize = 1500;
const RELAY_PATH_MTU_MINIMUM: usize = 576;
const RELAY_PATH_MTU_REFRESH_INTERVAL_MS: u64 = 5_000;

/// Keepalive interval to maintain NAT bindings - 15s is safer for strict NATs
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Read timeout - only affects idle wakeups (packets wake the socket immediately).
/// Higher values reduce CPU usage when idle without adding latency when active.
const READ_TIMEOUT: Duration = Duration::from_millis(50);

/// Grace period after relay switch: accept packets from BOTH old and new relay.
/// This eliminates the inbound blackout while the new relay establishes session.
const RELAY_SWITCH_GRACE_PERIOD: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayAuthAckStatus {
    Ok = 0,
    BadFormat = 1,
    BadSignature = 2,
    Expired = 3,
    SidMismatch = 4,
    ServerMismatch = 5,
    AuthDisabled = 6,
}

impl RelayAuthAckStatus {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            1 => Some(Self::BadFormat),
            2 => Some(Self::BadSignature),
            3 => Some(Self::Expired),
            4 => Some(Self::SidMismatch),
            5 => Some(Self::ServerMismatch),
            6 => Some(Self::AuthDisabled),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::BadFormat => "bad_format",
            Self::BadSignature => "bad_signature",
            Self::Expired => "expired",
            Self::SidMismatch => "sid_mismatch",
            Self::ServerMismatch => "server_mismatch",
            Self::AuthDisabled => "auth_disabled",
        }
    }
}

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
    /// Inner packets dropped because encapsulation would exceed path MTU.
    oversize_drops: AtomicU64,
    /// Effective outer MTU for relay packets (<= 1500), refreshed periodically on Windows.
    relay_path_mtu: AtomicUsize,
    last_mtu_refresh_ms: AtomicU64,
    /// Last activity time for keepalive
    last_activity: std::sync::Mutex<Instant>,
}

impl UdpRelay {
    /// Create a new UDP relay connection to the specified server
    ///
    /// relay_addr should already be resolved (use tokio::net::lookup_host for DNS)
    pub fn new(relay_addr: SocketAddr) -> Result<Self> {
        // Bind to any available port
        let socket = UdpSocket::bind("0.0.0.0:0").context("Failed to bind UDP socket")?;

        // Set socket options for low latency
        socket
            .set_read_timeout(Some(READ_TIMEOUT))
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
                let buf_bytes = std::slice::from_raw_parts(&buf_size as *const i32 as *const u8, 4);

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

        let initial_mtu = detect_relay_path_mtu(relay_addr).unwrap_or(RELAY_PATH_MTU_UPPER_BOUND);
        let initial_mtu = initial_mtu.clamp(RELAY_PATH_MTU_MINIMUM, RELAY_PATH_MTU_UPPER_BOUND);

        Ok(Self {
            socket,
            relay_addr: ArcSwap::from_pointee(relay_addr),
            previous_relay_addr: ArcSwap::from_pointee(None),
            switch_time: ArcSwap::from_pointee(None),
            session_id,
            stop_flag: Arc::new(AtomicBool::new(false)),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            oversize_drops: AtomicU64::new(0),
            relay_path_mtu: AtomicUsize::new(initial_mtu),
            last_mtu_refresh_ms: AtomicU64::new(now_mono_ms()),
            last_activity: std::sync::Mutex::new(Instant::now()),
        })
    }

    /// Get the session ID as a u64 for logging
    pub fn session_id_u64(&self) -> u64 {
        u64::from_be_bytes(self.session_id)
    }

    /// Get the session ID as lower-case hex string.
    pub fn session_id_hex(&self) -> String {
        format!("{:016x}", self.session_id_u64())
    }

    fn max_inner_packet_len_for_addr(&self, relay_addr: SocketAddr) -> usize {
        let mtu = self.relay_path_mtu.load(Ordering::Relaxed);
        let overhead = if relay_addr.ip().is_ipv4() {
            IPV4_HEADER_LEN + UDP_HEADER_LEN + SESSION_ID_LEN
        } else {
            IPV6_HEADER_LEN + UDP_HEADER_LEN + SESSION_ID_LEN
        };
        mtu.saturating_sub(overhead)
    }

    #[cfg(windows)]
    fn maybe_refresh_relay_path_mtu(&self, relay_addr: SocketAddr) {
        let now = now_mono_ms();
        let last = self.last_mtu_refresh_ms.load(Ordering::Relaxed);
        if now.saturating_sub(last) < RELAY_PATH_MTU_REFRESH_INTERVAL_MS {
            return;
        }

        if self
            .last_mtu_refresh_ms
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        if let Some(mtu) = detect_relay_path_mtu(relay_addr) {
            let mtu = mtu.clamp(RELAY_PATH_MTU_MINIMUM, RELAY_PATH_MTU_UPPER_BOUND);
            let prev = self.relay_path_mtu.swap(mtu, Ordering::Relaxed);
            if prev != mtu {
                log::info!(
                    "UDP Relay: Updated relay path MTU {} -> {} for {}",
                    prev,
                    mtu,
                    relay_addr
                );
            }
        }
    }

    #[cfg(not(windows))]
    fn maybe_refresh_relay_path_mtu(&self, _relay_addr: SocketAddr) {}

    #[cfg(test)]
    fn set_relay_path_mtu_for_test(&self, mtu: usize) {
        let mtu = mtu.clamp(RELAY_PATH_MTU_MINIMUM, RELAY_PATH_MTU_UPPER_BOUND);
        self.relay_path_mtu.store(mtu, Ordering::Relaxed);
    }

    fn is_expected_relay_source(&self, from: SocketAddr) -> bool {
        let expected_addr = **self.relay_addr.load();
        if from == expected_addr {
            return true;
        }

        if let (Some(prev), Some(switched_at)) = (
            (**self.previous_relay_addr.load()).as_ref(),
            (**self.switch_time.load()).as_ref(),
        ) {
            return from == *prev && switched_at.elapsed() < RELAY_SWITCH_GRACE_PERIOD;
        }
        false
    }

    /// Send relay auth hello frame:
    /// [session_id:8][0xA1][token_len:2][token_utf8].
    pub fn send_auth_hello(&self, token: &str) -> Result<()> {
        let token_bytes = token.as_bytes();
        if token_bytes.is_empty() || token_bytes.len() > u16::MAX as usize {
            anyhow::bail!(
                "Relay auth token length must be between 1 and {} bytes",
                u16::MAX
            );
        }

        let mut frame = Vec::with_capacity(SESSION_ID_LEN + 3 + token_bytes.len());
        frame.extend_from_slice(&self.session_id);
        frame.push(AUTH_HELLO_FRAME_TYPE);
        frame.extend_from_slice(&(token_bytes.len() as u16).to_be_bytes());
        frame.extend_from_slice(token_bytes);

        let current_addr = **self.relay_addr.load();
        self.socket
            .send_to(&frame, current_addr)
            .context("Failed to send relay auth hello")?;
        log::debug!(
            "UDP Relay: Sent auth hello to {} (session {:016x}, token {} bytes)",
            current_addr,
            self.session_id_u64(),
            token_bytes.len()
        );
        Ok(())
    }

    fn wait_for_auth_ack_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Option<RelayAuthAckStatus>> {
        let deadline = Instant::now() + timeout;
        let mut recv_buf = [0u8; 1600];

        while Instant::now() < deadline {
            match self.socket.recv_from(&mut recv_buf) {
                Ok((len, from)) => {
                    if !self.is_expected_relay_source(from) {
                        continue;
                    }

                    if len < SESSION_ID_LEN + 2 {
                        continue;
                    }
                    if &recv_buf[..SESSION_ID_LEN] != &self.session_id {
                        continue;
                    }
                    if recv_buf[SESSION_ID_LEN] != AUTH_ACK_FRAME_TYPE {
                        continue;
                    }

                    let status_byte = recv_buf[SESSION_ID_LEN + 1];
                    let status = RelayAuthAckStatus::from_u8(status_byte)
                        .unwrap_or(RelayAuthAckStatus::BadFormat);
                    return Ok(Some(status));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                Err(e) => return Err(e.into()),
            }
        }

        Ok(None)
    }

    /// Send relay auth hello and wait for ack.
    ///
    /// Attempts: up to 4 within a total 1.5s wait budget.
    pub fn authenticate_with_ticket(&self, token: &str) -> Result<Option<RelayAuthAckStatus>> {
        let deadline = Instant::now() + AUTH_HANDSHAKE_TOTAL_TIMEOUT;

        for attempt in 0..AUTH_HANDSHAKE_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(AUTH_HANDSHAKE_RETRY_DELAY);
            }

            self.send_auth_hello(token)?;

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            if let Some(status) = self.wait_for_auth_ack_with_timeout(remaining)? {
                log::info!(
                    "UDP Relay: Auth ack {} for session {:016x}",
                    status.as_str(),
                    self.session_id_u64()
                );
                return Ok(Some(status));
            }
        }

        Ok(None)
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
        let current_addr = **self.relay_addr.load();
        self.maybe_refresh_relay_path_mtu(current_addr);
        let max_payload = self.max_inner_packet_len_for_addr(current_addr);

        if payload.len() > max_payload {
            let dropped = self.oversize_drops.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped <= 5 || dropped.is_power_of_two() {
                let mtu = self.relay_path_mtu.load(Ordering::Relaxed);
                let overhead = mtu.saturating_sub(max_payload);
                log::warn!(
                    "UDP Relay: Inner packet too large for encapsulation ({} > {} bytes). \
                    Dropping to avoid fragmentation (relay path MTU {}, overhead {} bytes, relay {}).",
                    payload.len(),
                    max_payload,
                    mtu,
                    overhead,
                    current_addr,
                );
            }
            return Ok(0);
        }

        // Build packet: [session_id][payload] on the stack (no heap alloc)
        let total_len = SESSION_ID_LEN + payload.len();
        let mut packet = [0u8; SESSION_ID_LEN + RELAY_PATH_MTU_UPPER_BOUND];
        packet[..SESSION_ID_LEN].copy_from_slice(&self.session_id);
        packet[SESSION_ID_LEN..total_len].copy_from_slice(payload);

        // Try to send, retry once on WouldBlock
        let sent = match self.socket.send_to(&packet[..total_len], current_addr) {
            Ok(sent) => sent,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Retry once after tiny delay
                std::thread::sleep(Duration::from_micros(50));
                self.socket
                    .send_to(&packet[..total_len], current_addr)
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
                if !self.is_expected_relay_source(from) {
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

                // Ignore relay control frames so they never reach packet injection.
                if payload_len >= 1
                    && matches!(
                        recv_buf[SESSION_ID_LEN],
                        AUTH_HELLO_FRAME_TYPE | AUTH_ACK_FRAME_TYPE
                    )
                {
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
        self.socket
            .send_to(&self.session_id, current_addr)
            .context("Failed to send immediate keepalive")?;
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = Instant::now();
        }
        log::info!(
            "UDP Relay: Sent immediate keepalive to {} (session {:016x})",
            current_addr,
            self.session_id_u64()
        );
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
            current_addr,
            self.session_id_u64()
        );
        Ok(())
    }

    /// Send keepalive to maintain NAT binding
    pub fn send_keepalive(&self) -> Result<()> {
        let should_send = self
            .last_activity
            .lock()
            .map(|guard| guard.elapsed() >= KEEPALIVE_INTERVAL)
            .unwrap_or(true); // If poisoned, send keepalive anyway

        if should_send {
            // Send empty payload with just session ID
            let current_addr = **self.relay_addr.load();
            self.socket
                .send_to(&self.session_id, current_addr)
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
            "UDP Relay: Stopped session {:016x} (sent: {}, recv: {}, oversize_drops: {})",
            self.session_id_u64(),
            self.packets_sent.load(Ordering::Relaxed),
            self.packets_received.load(Ordering::Relaxed),
            self.oversize_drops.load(Ordering::Relaxed),
        );
    }

    /// Clone the socket for use in inbound receiver thread
    pub fn try_clone_socket(&self) -> Result<UdpSocket> {
        self.socket
            .try_clone()
            .context("Failed to clone relay socket")
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
            old_addr,
            new_addr,
            self.session_id_u64(),
            RELAY_SWITCH_GRACE_PERIOD.as_secs()
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

fn now_mono_ms() -> u64 {
    #[cfg(windows)]
    unsafe {
        return windows::Win32::System::SystemInformation::GetTickCount64();
    }

    #[cfg(not(windows))]
    {
        use std::sync::OnceLock;
        static START: OnceLock<Instant> = OnceLock::new();
        let start = START.get_or_init(Instant::now);
        start.elapsed().as_millis() as u64
    }
}

fn detect_relay_path_mtu(relay_addr: SocketAddr) -> Option<usize> {
    #[cfg(windows)]
    {
        use windows::Win32::NetworkManagement::IpHelper::{
            GetBestInterfaceEx, GetIfEntry2, MIB_IF_ROW2,
        };
        use windows::Win32::Networking::WinSock::{
            AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR, SOCKADDR_IN,
            SOCKADDR_IN6, SOCKADDR_IN6_0,
        };

        let mut if_index: u32 = 0;

        let rc = match relay_addr {
            SocketAddr::V4(addr) => {
                let ip_octets = addr.ip().octets();
                let sockaddr_in = SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: 0,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(ip_octets),
                        },
                    },
                    sin_zero: [0; 8],
                };
                unsafe {
                    GetBestInterfaceEx(
                        &sockaddr_in as *const SOCKADDR_IN as *const SOCKADDR,
                        &mut if_index,
                    )
                }
            }
            SocketAddr::V6(addr) => {
                let ip_octets = addr.ip().octets();
                let sockaddr_in6 = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 { Byte: ip_octets },
                    },
                    Anonymous: SOCKADDR_IN6_0 {
                        sin6_scope_id: addr.scope_id(),
                    },
                };
                unsafe {
                    GetBestInterfaceEx(
                        &sockaddr_in6 as *const SOCKADDR_IN6 as *const SOCKADDR,
                        &mut if_index,
                    )
                }
            }
        };

        if rc != 0 {
            return None;
        }

        let mut row = MIB_IF_ROW2::default();
        row.InterfaceIndex = if_index;
        let rc = unsafe { GetIfEntry2(&mut row) };
        if rc.0 != 0 {
            return None;
        }

        return Some(row.Mtu as usize);
    }

    #[cfg(not(windows))]
    {
        let _ = relay_addr;
        None
    }
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

    #[test]
    fn test_forward_outbound_drops_oversize_payload() {
        let relay = UdpRelay::new("127.0.0.1:51821".parse().unwrap()).unwrap();
        relay.set_relay_path_mtu_for_test(1500);
        let max_payload = relay.max_inner_packet_len_for_addr("127.0.0.1:51821".parse().unwrap());
        let payload = vec![0u8; max_payload + 1];
        let sent = relay.forward_outbound(&payload).unwrap();
        assert_eq!(sent, 0);
        assert_eq!(relay.oversize_drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_forward_outbound_allows_max_payload() {
        let relay = UdpRelay::new("127.0.0.1:51821".parse().unwrap()).unwrap();
        relay.set_relay_path_mtu_for_test(1500);
        let max_payload = relay.max_inner_packet_len_for_addr("127.0.0.1:51821".parse().unwrap());
        let payload = vec![0u8; max_payload];
        let sent = relay.forward_outbound(&payload).unwrap();
        assert_eq!(sent, SESSION_ID_LEN + max_payload);
    }

    #[test]
    fn test_forward_outbound_respects_lower_path_mtu() {
        let relay = UdpRelay::new("127.0.0.1:51821".parse().unwrap()).unwrap();
        relay.set_relay_path_mtu_for_test(1400);
        let max_payload = relay.max_inner_packet_len_for_addr("127.0.0.1:51821".parse().unwrap());
        assert_eq!(
            max_payload,
            1400 - (IPV4_HEADER_LEN + UDP_HEADER_LEN + SESSION_ID_LEN)
        );

        let payload = vec![0u8; max_payload + 1];
        let sent = relay.forward_outbound(&payload).unwrap();
        assert_eq!(sent, 0);
        assert_eq!(relay.oversize_drops.load(Ordering::Relaxed), 1);
    }
}
