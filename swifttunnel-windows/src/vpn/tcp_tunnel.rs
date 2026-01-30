//! TCP Tunnel for Stealth Mode (Phantun)
//!
//! This module implements a local TCP-to-UDP proxy for bypassing DPI and UDP blocks.
//!
//! ## How it works:
//! 1. WireGuard connects to localhost:51821 (UDP)
//! 2. TcpTunnel receives UDP packets, frames them with [u16 len][payload]
//! 3. Sends framed packets over TCP to server:443 (Phantun)
//! 4. Server's Phantun unwraps and delivers to WireGuard on port 51820
//! 5. Reverse path for responses
//!
//! ## Framing Protocol:
//! Each UDP packet is prefixed with a 2-byte big-endian length:
//! ```text
//! [u16 len (big-endian)][payload...]
//! ```
//!
//! This matches the Phantun server's expected framing format.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

/// Local UDP port for WireGuard to connect to
const LOCAL_UDP_PORT: u16 = 51821;

/// TCP tunnel for stealth mode (Phantun)
///
/// Proxies UDP traffic from local WireGuard through TCP to the VPN server's
/// Phantun endpoint on port 443.
pub struct TcpTunnel {
    /// Flag to signal shutdown
    stop_flag: Arc<AtomicBool>,
    /// Server endpoint (IP:443)
    server_addr: SocketAddr,
    /// Local UDP address that WireGuard should connect to
    local_addr: SocketAddr,
    /// Tokio task handles for cleanup
    task_handles: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl TcpTunnel {
    /// Create a new TCP tunnel (but don't start it yet)
    pub fn new(server_ip: std::net::Ipv4Addr, phantun_port: u16) -> Self {
        let server_addr = SocketAddr::new(server_ip.into(), phantun_port);
        let local_addr = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            LOCAL_UDP_PORT,
        );

        Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
            server_addr,
            local_addr,
            task_handles: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Start the TCP tunnel
    ///
    /// Returns Ok(local_addr) where WireGuard should connect
    pub async fn start(&self) -> Result<SocketAddr, TcpTunnelError> {
        self.stop_flag.store(false, Ordering::SeqCst);

        // Connect to server's Phantun endpoint over TCP
        log::info!("TCP tunnel: Connecting to Phantun server at {}", self.server_addr);
        let tcp_stream = TcpStream::connect(self.server_addr)
            .await
            .map_err(|e| TcpTunnelError::TcpConnect(e.to_string()))?;

        // Configure TCP for low latency
        tcp_stream.set_nodelay(true)
            .map_err(|e| TcpTunnelError::TcpConfig(e.to_string()))?;

        log::info!("TCP tunnel: Connected to Phantun server");

        // Bind local UDP socket for WireGuard
        let udp_socket = UdpSocket::bind(self.local_addr)
            .await
            .map_err(|e| TcpTunnelError::UdpBind(e.to_string()))?;

        log::info!("TCP tunnel: Listening for WireGuard on {}", self.local_addr);

        // Split TCP stream for bidirectional I/O
        let (tcp_reader, tcp_writer) = tcp_stream.into_split();
        let tcp_writer = Arc::new(Mutex::new(tcp_writer));
        let tcp_reader = Arc::new(Mutex::new(tcp_reader));

        // Share UDP socket between tasks
        let udp_socket = Arc::new(udp_socket);

        // Track the WireGuard peer address (set when first packet arrives)
        let peer_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

        // Start relay tasks
        let stop_1 = Arc::clone(&self.stop_flag);
        let stop_2 = Arc::clone(&self.stop_flag);
        let tcp_writer_clone = Arc::clone(&tcp_writer);
        let udp_socket_1 = Arc::clone(&udp_socket);
        let udp_socket_2 = Arc::clone(&udp_socket);
        let peer_addr_1 = Arc::clone(&peer_addr);
        let peer_addr_2 = Arc::clone(&peer_addr);

        // UDP -> TCP relay (outbound: WireGuard packets to server)
        let outbound_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048]; // WireGuard max packet is ~1500

            loop {
                if stop_1.load(Ordering::SeqCst) {
                    log::debug!("TCP tunnel outbound: Stop flag set, exiting");
                    break;
                }

                // Receive UDP packet from WireGuard with timeout
                let recv_result = tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    udp_socket_1.recv_from(&mut buf)
                ).await;

                let (len, addr) = match recv_result {
                    Ok(Ok((len, addr))) => (len, addr),
                    Ok(Err(e)) => {
                        log::warn!("TCP tunnel outbound: UDP recv error: {}", e);
                        continue;
                    }
                    Err(_) => continue, // Timeout, check stop flag
                };

                // Remember peer address for responses
                {
                    let mut peer = peer_addr_1.lock().await;
                    if peer.is_none() {
                        log::debug!("TCP tunnel: WireGuard peer at {}", addr);
                        *peer = Some(addr);
                    }
                }

                // Frame the packet: [u16 len][payload]
                // Validate packet size fits in u16 (theoretical max, WireGuard MTU is ~1420)
                if len > u16::MAX as usize {
                    log::error!("TCP tunnel outbound: Packet too large: {} bytes", len);
                    continue;
                }
                let mut frame = Vec::with_capacity(2 + len);
                frame.extend_from_slice(&(len as u16).to_be_bytes());
                frame.extend_from_slice(&buf[..len]);

                // Send over TCP
                let mut writer = tcp_writer_clone.lock().await;
                if let Err(e) = writer.write_all(&frame).await {
                    log::error!("TCP tunnel outbound: TCP write error: {}", e);
                    stop_1.store(true, Ordering::SeqCst);
                    break;
                }
            }

            log::info!("TCP tunnel outbound task exited");
        });

        // TCP -> UDP relay (inbound: server responses to WireGuard)
        let inbound_task = tokio::spawn(async move {
            let mut len_buf = [0u8; 2];
            let mut payload_buf = vec![0u8; 2048];

            loop {
                if stop_2.load(Ordering::SeqCst) {
                    log::debug!("TCP tunnel inbound: Stop flag set, exiting");
                    break;
                }

                // Read frame length with timeout
                let mut reader = tcp_reader.lock().await;
                let read_result = tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    reader.read_exact(&mut len_buf)
                ).await;

                let _ = match read_result {
                    Ok(Ok(_)) => (),
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        log::info!("TCP tunnel inbound: Connection closed by server");
                        stop_2.store(true, Ordering::SeqCst);
                        break;
                    }
                    Ok(Err(e)) => {
                        log::error!("TCP tunnel inbound: TCP read error: {}", e);
                        stop_2.store(true, Ordering::SeqCst);
                        break;
                    }
                    Err(_) => {
                        drop(reader);
                        continue; // Timeout, check stop flag
                    }
                };

                let payload_len = u16::from_be_bytes(len_buf) as usize;
                // Validate payload length - zero or oversized packets corrupt the stream
                if payload_len == 0 || payload_len > payload_buf.len() {
                    log::error!("TCP tunnel inbound: Invalid payload length: {} (must be 1-{})", payload_len, payload_buf.len());
                    stop_2.store(true, Ordering::SeqCst);
                    break;
                }

                // Read payload
                if let Err(e) = reader.read_exact(&mut payload_buf[..payload_len]).await {
                    log::error!("TCP tunnel inbound: TCP payload read error: {}", e);
                    stop_2.store(true, Ordering::SeqCst);
                    break;
                }

                drop(reader);

                // Send to WireGuard via UDP
                let peer = peer_addr_2.lock().await;
                if let Some(addr) = *peer {
                    if let Err(e) = udp_socket_2.send_to(&payload_buf[..payload_len], addr).await {
                        log::warn!("TCP tunnel inbound: UDP send error: {}", e);
                    }
                } else {
                    log::debug!("TCP tunnel inbound: No peer address yet, dropping packet");
                }
            }

            log::info!("TCP tunnel inbound task exited");
        });

        // Store task handles
        let mut handles = self.task_handles.lock().await;
        handles.push(outbound_task);
        handles.push(inbound_task);

        log::info!("TCP tunnel started - relay tasks running");
        Ok(self.local_addr)
    }

    /// Stop the TCP tunnel
    pub async fn stop(&self) {
        log::info!("TCP tunnel: Stopping...");
        self.stop_flag.store(true, Ordering::SeqCst);

        // Wait for tasks to finish (with timeout)
        let mut handles = self.task_handles.lock().await;
        for handle in handles.drain(..) {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                handle
            ).await;
        }

        log::info!("TCP tunnel: Stopped");
    }

    /// Get the local address that WireGuard should connect to
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Check if the tunnel is currently running
    pub fn is_running(&self) -> bool {
        !self.stop_flag.load(Ordering::SeqCst)
    }
}

impl Drop for TcpTunnel {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}

/// Errors that can occur with the TCP tunnel
#[derive(Debug, thiserror::Error)]
pub enum TcpTunnelError {
    #[error("TCP connection failed: {0}")]
    TcpConnect(String),

    #[error("TCP configuration error: {0}")]
    TcpConfig(String),

    #[error("UDP bind failed: {0}")]
    UdpBind(String),

    #[error("Tunnel not connected")]
    NotConnected,

    #[error("Relay error: {0}")]
    RelayError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_framing() {
        // Test length prefix encoding
        let len: u16 = 1500;
        let bytes = len.to_be_bytes();
        assert_eq!(bytes, [0x05, 0xDC]); // 1500 in big-endian

        let decoded = u16::from_be_bytes(bytes);
        assert_eq!(decoded, 1500);
    }

    #[test]
    fn test_local_addr() {
        let tunnel = TcpTunnel::new(
            std::net::Ipv4Addr::new(127, 0, 0, 1),
            443
        );
        let addr = tunnel.local_addr();
        assert_eq!(addr.port(), LOCAL_UDP_PORT);
    }
}
