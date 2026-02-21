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
use crossbeam_channel as channel;
use std::cell::UnsafeCell;
use std::collections::VecDeque;
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
const PING_FRAME_TYPE: u8 = 0xA3;
const PONG_FRAME_TYPE: u8 = 0xA4;
const PING_FRAME_LEN: usize = SESSION_ID_LEN + 1 + 4 + 8;
const PONG_FRAME_LEN: usize = SESSION_ID_LEN + 1 + 4 + 8 + 8;
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

/// Outbound send path: bounded queue + fixed buffer pool.
///
/// This avoids per-packet heap allocations and eliminates multi-threaded contention
/// on Winsock send calls from per-CPU packet workers (reduces p99 jitter).
const OUTBOUND_FRAME_MAX: usize = SESSION_ID_LEN + RELAY_PATH_MTU_UPPER_BOUND;
const OUTBOUND_POOL_SLOTS: usize = 4096;
const OUTBOUND_QUEUE_CAP: usize = 4096;

/// Control-plane ping for RTT/jitter telemetry (optional).
const PING_INTERVAL: Duration = Duration::from_millis(50); // 20Hz
const PING_IDLE_THRESHOLD: Duration = Duration::from_secs(2);
const PING_IDLE_INTERVAL: Duration = Duration::from_millis(250);
const PING_SAMPLE_WINDOW: usize = 1024;

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

#[derive(Clone, Copy)]
struct OutboundJob {
    addr: SocketAddr,
    buf_idx: usize,
    len: usize,
}

struct OutboundPool {
    buffers: Vec<UnsafeCell<[u8; OUTBOUND_FRAME_MAX]>>,
    free_tx: channel::Sender<usize>,
    free_rx: channel::Receiver<usize>,
}

// Safety: buffer indices are checked out exclusively via the free list.
unsafe impl Sync for OutboundPool {}
unsafe impl Send for OutboundPool {}

impl OutboundPool {
    fn new(slots: usize) -> Self {
        let (free_tx, free_rx) = channel::bounded(slots);
        let mut buffers = Vec::with_capacity(slots);
        for i in 0..slots {
            buffers.push(UnsafeCell::new([0u8; OUTBOUND_FRAME_MAX]));
            free_tx
                .send(i)
                .expect("outbound pool free list must accept initial slots");
        }
        Self {
            buffers,
            free_tx,
            free_rx,
        }
    }

    fn try_acquire(&self) -> Option<usize> {
        self.free_rx.try_recv().ok()
    }

    fn release(&self, idx: usize) {
        let _ = self.free_tx.send(idx);
    }

    unsafe fn buffer_mut(&self, idx: usize) -> &mut [u8; OUTBOUND_FRAME_MAX] {
        &mut *self.buffers[idx].get()
    }

    unsafe fn buffer(&self, idx: usize) -> &[u8; OUTBOUND_FRAME_MAX] {
        &*self.buffers[idx].get()
    }
}

#[derive(Debug, Clone)]
pub struct RelayPingSnapshot {
    pub enabled: bool,
    pub sent: u64,
    pub received: u64,
    pub loss_pct: f32,
    pub last_rtt_ms: Option<u32>,
    pub p50_rtt_ms: Option<u32>,
    pub p99_rtt_ms: Option<u32>,
    pub sample_count: usize,
}

struct PingMetrics {
    enabled: AtomicBool,
    sent: AtomicU64,
    received: AtomicU64,
    last_rtt_ms: AtomicU64,
    samples: std::sync::Mutex<VecDeque<u32>>,
}

impl PingMetrics {
    fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            last_rtt_ms: AtomicU64::new(0),
            samples: std::sync::Mutex::new(VecDeque::with_capacity(PING_SAMPLE_WINDOW)),
        }
    }

    fn record_rtt_ms(&self, rtt_ms: u32) {
        self.received.fetch_add(1, Ordering::Relaxed);
        self.last_rtt_ms.store(rtt_ms as u64, Ordering::Relaxed);

        if let Ok(mut samples) = self.samples.lock() {
            if samples.len() >= PING_SAMPLE_WINDOW {
                samples.pop_front();
            }
            samples.push_back(rtt_ms);
        }
    }

    fn snapshot(&self) -> RelayPingSnapshot {
        let enabled = self.enabled.load(Ordering::Acquire);
        let sent = self.sent.load(Ordering::Relaxed);
        let received = self.received.load(Ordering::Relaxed);
        let loss_pct = if sent == 0 {
            0.0
        } else {
            let lost = sent.saturating_sub(received);
            (lost as f32) * 100.0 / (sent as f32)
        };
        let last_rtt_raw = self.last_rtt_ms.load(Ordering::Relaxed);
        let last_rtt_ms = if last_rtt_raw == 0 {
            None
        } else {
            Some(last_rtt_raw as u32)
        };

        let mut p50_rtt_ms: Option<u32> = None;
        let mut p99_rtt_ms: Option<u32> = None;
        let mut sample_count = 0usize;

        if let Ok(samples) = self.samples.lock() {
            sample_count = samples.len();
            if sample_count > 0 {
                let mut values: Vec<u32> = samples.iter().copied().collect();
                values.sort_unstable();
                let p50_idx = ((values.len() - 1) as f64 * 0.50).round() as usize;
                let p99_idx = ((values.len() - 1) as f64 * 0.99).floor() as usize;
                p50_rtt_ms = values.get(p50_idx).copied();
                p99_rtt_ms = values.get(p99_idx).copied();
            }
        }

        RelayPingSnapshot {
            enabled,
            sent,
            received,
            loss_pct,
            last_rtt_ms,
            p50_rtt_ms,
            p99_rtt_ms,
            sample_count,
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
    /// Outbound frames dropped due to send queue pressure.
    outbound_drops: AtomicU64,
    /// Effective outer MTU for relay packets (<= 1500), refreshed periodically on Windows.
    relay_path_mtu: AtomicUsize,
    last_mtu_refresh_ms: AtomicU64,
    /// Last activity time for keepalive
    last_activity: std::sync::Mutex<Instant>,
    outbound_pool: Arc<OutboundPool>,
    outbound_tx: channel::Sender<OutboundJob>,
    ping: Arc<PingMetrics>,
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

        let stop_flag = Arc::new(AtomicBool::new(false));

        // Dedicated sender thread: eliminates multi-threaded Winsock send contention.
        let outbound_pool = Arc::new(OutboundPool::new(OUTBOUND_POOL_SLOTS));
        let (outbound_tx, outbound_rx) = channel::bounded::<OutboundJob>(OUTBOUND_QUEUE_CAP);
        let ping = Arc::new(PingMetrics::new());

        let sender_socket = socket
            .try_clone()
            .context("Failed to clone UDP socket for sender thread")?;
        let sender_pool = Arc::clone(&outbound_pool);
        let sender_stop = Arc::clone(&stop_flag);
        let sender_ping = Arc::clone(&ping);
        let sender_session_id = session_id;
        std::thread::Builder::new()
            .name("udp-relay-sender".to_string())
            .spawn(move || {
                let mut last_relay_addr: Option<SocketAddr> = None;
                let mut last_data_at: Option<Instant> = None;
                let mut ping_seq: u32 = 0;
                let mut next_ping_at = Instant::now() + PING_INTERVAL;

                loop {
                    if sender_stop.load(Ordering::Acquire) {
                        break;
                    }

                    // Wait for outbound work, but wake periodically to service ping timing.
                    let now = Instant::now();
                    let timeout = next_ping_at
                        .saturating_duration_since(now)
                        .min(Duration::from_millis(50));

                    match outbound_rx.recv_timeout(timeout) {
                        Ok(job) => {
                            last_relay_addr = Some(job.addr);
                            last_data_at = Some(Instant::now());

                            // Send and release buffer slot.
                            let bytes = unsafe { sender_pool.buffer(job.buf_idx) };
                            let _ = sender_socket.send_to(&bytes[..job.len], job.addr);
                            sender_pool.release(job.buf_idx);
                        }
                        Err(channel::RecvTimeoutError::Timeout) => {}
                        Err(channel::RecvTimeoutError::Disconnected) => break,
                    }

                    let now = Instant::now();
                    if !sender_ping.enabled.load(Ordering::Acquire) {
                        continue;
                    }

                    let Some(relay_addr) = last_relay_addr else {
                        continue;
                    };

                    let Some(last_data_at) = last_data_at else {
                        continue;
                    };

                    // Back off pings when idle to avoid noisy telemetry at rest.
                    if now.duration_since(last_data_at) >= PING_IDLE_THRESHOLD {
                        next_ping_at = now + PING_IDLE_INTERVAL;
                        continue;
                    }

                    if now < next_ping_at {
                        continue;
                    }

                    ping_seq = ping_seq.wrapping_add(1);
                    let client_ts_mono_ms = now_mono_ms();

                    let mut frame = [0u8; PING_FRAME_LEN];
                    frame[..SESSION_ID_LEN].copy_from_slice(&sender_session_id);
                    frame[SESSION_ID_LEN] = PING_FRAME_TYPE;
                    frame[SESSION_ID_LEN + 1..SESSION_ID_LEN + 5]
                        .copy_from_slice(&ping_seq.to_be_bytes());
                    frame[SESSION_ID_LEN + 5..SESSION_ID_LEN + 13]
                        .copy_from_slice(&client_ts_mono_ms.to_be_bytes());

                    let _ = sender_socket.send_to(&frame, relay_addr);
                    sender_ping.sent.fetch_add(1, Ordering::Relaxed);
                    next_ping_at = now + PING_INTERVAL;
                }

                // Drain any queued jobs to return buffer slots to the free list.
                while let Ok(job) = outbound_rx.try_recv() {
                    sender_pool.release(job.buf_idx);
                }
            })
            .context("Failed to spawn udp-relay-sender thread")?;

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
            stop_flag,
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            oversize_drops: AtomicU64::new(0),
            outbound_drops: AtomicU64::new(0),
            relay_path_mtu: AtomicUsize::new(initial_mtu),
            last_mtu_refresh_ms: AtomicU64::new(now_mono_ms()),
            last_activity: std::sync::Mutex::new(Instant::now()),
            outbound_pool,
            outbound_tx,
            ping,
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

    /// Enable or disable control-plane ping telemetry.
    pub fn set_ping_enabled(&self, enabled: bool) {
        self.ping.enabled.store(enabled, Ordering::Release);
    }

    pub fn ping_snapshot(&self) -> RelayPingSnapshot {
        self.ping.snapshot()
    }

    /// Forward a packet through the relay (outbound: game client -> relay -> game server)
    ///
    /// Takes the original UDP payload and prepends session ID before enqueueing to the
    /// dedicated sender thread.
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

        let total_len = SESSION_ID_LEN + payload.len();

        let Some(buf_idx) = self.outbound_pool.try_acquire() else {
            self.outbound_drops.fetch_add(1, Ordering::Relaxed);
            return Ok(0);
        };

        unsafe {
            let packet = self.outbound_pool.buffer_mut(buf_idx);
            packet[..SESSION_ID_LEN].copy_from_slice(&self.session_id);
            packet[SESSION_ID_LEN..total_len].copy_from_slice(payload);
        }

        let job = OutboundJob {
            addr: current_addr,
            buf_idx,
            len: total_len,
        };
        if self.outbound_tx.try_send(job).is_err() {
            self.outbound_drops.fetch_add(1, Ordering::Relaxed);
            self.outbound_pool.release(buf_idx);
            return Ok(0);
        }

        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = Instant::now();
        }

        Ok(total_len)
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

                // Control frames (auth + ping telemetry) should never reach packet injection.
                if payload_len >= 1 {
                    match recv_buf[SESSION_ID_LEN] {
                        AUTH_HELLO_FRAME_TYPE | AUTH_ACK_FRAME_TYPE | PING_FRAME_TYPE => {
                            return Ok(None);
                        }
                        PONG_FRAME_TYPE => {
                            if len == PONG_FRAME_LEN && self.ping.enabled.load(Ordering::Acquire) {
                                let client_ts_mono_ms = u64::from_be_bytes([
                                    recv_buf[SESSION_ID_LEN + 5],
                                    recv_buf[SESSION_ID_LEN + 6],
                                    recv_buf[SESSION_ID_LEN + 7],
                                    recv_buf[SESSION_ID_LEN + 8],
                                    recv_buf[SESSION_ID_LEN + 9],
                                    recv_buf[SESSION_ID_LEN + 10],
                                    recv_buf[SESSION_ID_LEN + 11],
                                    recv_buf[SESSION_ID_LEN + 12],
                                ]);
                                let now_ms = now_mono_ms();
                                if now_ms >= client_ts_mono_ms {
                                    let rtt_ms = (now_ms - client_ts_mono_ms) as u32;
                                    self.ping.record_rtt_ms(rtt_ms);
                                }
                            }
                            return Ok(None);
                        }
                        _ => {}
                    }
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
        let ping = self.ping.snapshot();
        log::info!(
            "UDP Relay: Stopped session {:016x} (sent: {}, recv: {}, oversize_drops: {}, outbound_drops: {}, ping: {}/{} {:.1}% loss)",
            self.session_id_u64(),
            self.packets_sent.load(Ordering::Relaxed),
            self.packets_received.load(Ordering::Relaxed),
            self.oversize_drops.load(Ordering::Relaxed),
            self.outbound_drops.load(Ordering::Relaxed),
            ping.sent,
            ping.received,
            ping.loss_pct,
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

    #[test]
    fn test_receive_inbound_ignores_pong_and_records_ping_stats() {
        let relay = UdpRelay::new("127.0.0.1:51821".parse().unwrap()).unwrap();
        relay.set_ping_enabled(true);

        // Use an ephemeral socket as our "relay server", then switch the expected source.
        let fake_relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        let fake_addr = fake_relay.local_addr().unwrap();
        relay.switch_relay(fake_addr);

        let local_addr = relay.try_clone_socket().unwrap().local_addr().unwrap();

        let seq: u32 = 1;
        let client_ts_mono_ms = now_mono_ms();
        let mut frame = [0u8; PONG_FRAME_LEN];
        frame[..SESSION_ID_LEN].copy_from_slice(relay.session_id_bytes());
        frame[SESSION_ID_LEN] = PONG_FRAME_TYPE;
        frame[SESSION_ID_LEN + 1..SESSION_ID_LEN + 5].copy_from_slice(&seq.to_be_bytes());
        frame[SESSION_ID_LEN + 5..SESSION_ID_LEN + 13]
            .copy_from_slice(&client_ts_mono_ms.to_be_bytes());
        frame[SESSION_ID_LEN + 13..SESSION_ID_LEN + 21].copy_from_slice(&0u64.to_be_bytes());

        fake_relay.send_to(&frame, local_addr).unwrap();

        let mut buffer = [0u8; 1600];
        let result = relay.receive_inbound(&mut buffer).unwrap();
        assert_eq!(result, None);

        let snap = relay.ping_snapshot();
        assert!(snap.received >= 1);
    }
}
